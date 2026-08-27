/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * PnetProtectedConnection tests over an in-memory byte-pipe harness:
 * round-trip, wire-leak, mismatched-PSK garbage, chunk storms, defer
 * semantics, close delegation, and the nonce-read failure path.
 */
#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <deque>
#include <memory>
#include <vector>

#include <libp2p/basic/scheduler.hpp>
#include <libp2p/log/configurator.hpp>
#include <libp2p/security/pnet/pnet_error.hpp>
#include <libp2p/security/pnet/pnet_protected_connection.hpp>
#include <libp2p/security/pnet/psk.hpp>

#include <libp2p/basic/scheduler/scheduler_impl.hpp>
#include <libp2p/basic/scheduler/manual_scheduler_backend.hpp>

using namespace libp2p::security::pnet;
using libp2p::basic::SchedulerImpl;
using libp2p::basic::ManualSchedulerBackend;

namespace {
  // 32-byte test PSK A: bytes 0x00..0x1f
  const std::vector<uint8_t> kPskABytes = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  // 32-byte test PSK B: bytes 0xff..0xe0 (deliberately different)
  const std::vector<uint8_t> kPskBBytes = {
      0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
      0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
      0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8,
      0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0};

  /**
   * Half of an in-memory byte pipe. writeSome appends into the peer's
   * inbound queue (synchronously completing any pending read) and
   * read/readSome complete from the local queue (synchronously if bytes are
   * available; otherwise parked until the peer writes).
   */
  class PipeEnd : public libp2p::connection::RawConnection {
   public:
    explicit PipeEnd(bool initiator) : initiator_(initiator) {}

    void setPeer(PipeEnd *peer) {
      peer_ = peer;
    }

    /// raw bytes that crossed the wire in the write direction (cleartext
    /// nonce + ciphertext) — for wire-leak assertions
    std::vector<uint8_t> written_on_wire;

    void read(gsl::span<uint8_t> out, size_t bytes,
              ReadCallbackFunc cb) override {
      // exact variant: park until ALL requested bytes are available
      readCommon(out, bytes, std::move(cb), true);
    }

    void readSome(gsl::span<uint8_t> out, size_t bytes,
                  ReadCallbackFunc cb) override {
      readCommon(out, bytes, std::move(cb), false);
    }

    void write(gsl::span<const uint8_t> in, size_t bytes,
               WriteCallbackFunc cb) override {
      writeSome(in, bytes, std::move(cb));
    }

    void writeSome(gsl::span<const uint8_t> in, size_t bytes,
                   WriteCallbackFunc cb) override {
      const size_t n = std::min(static_cast<size_t>(in.size()), bytes);
      // simulate the wire: record what would leave in the clear
      written_on_wire.insert(written_on_wire.end(), in.begin(), in.begin() + n);
      peer_->incoming_.insert(peer_->incoming_.end(), in.begin(),
                              in.begin() + n);
      peer_->wakePending();
      cb(n);
    }

    libp2p::outcome::result<void> close() override {
      return libp2p::outcome::success();
    }
    bool isClosed() const override {
      return false;
    }
    bool isInitiator() const noexcept override {
      return initiator_;
    }
    libp2p::outcome::result<libp2p::multi::Multiaddress> localMultiaddr()
        override {
      return std::errc::not_supported;
    }
    libp2p::outcome::result<libp2p::multi::Multiaddress> remoteMultiaddr()
        override {
      return std::errc::not_supported;
    }

    void deferReadCallback(libp2p::outcome::result<size_t> res,
                           ReadCallbackFunc cb) override {
      cb(res);
    }
    void deferWriteCallback(std::error_code ec,
                            WriteCallbackFunc cb) override {
      cb(ec);
    }

   private:
    struct PendingRead {
      gsl::span<uint8_t> out;
      size_t want;
      ReadCallbackFunc cb;
      bool exact;
    };

    void readCommon(gsl::span<uint8_t> out, size_t bytes, ReadCallbackFunc cb,
                    bool exact) {
      const size_t want = std::min(static_cast<size_t>(out.size()), bytes);
      pending_ = PendingRead{out, want, std::move(cb), exact};
      wakePending();
    }

    void wakePending() {
      if (!pending_.has_value()) {
        return;
      }
      auto &p = *pending_;
      const size_t avail = incoming_.size();
      const size_t take = exactness(p, avail);
      if (take == 0) {
        return;  // still waiting for more bytes
      }
      std::copy_n(incoming_.begin(), take, p.out.begin());
      incoming_.erase(incoming_.begin(),
                      incoming_.begin() + static_cast<ssize_t>(take));
      auto cb = std::move(p.cb);
      pending_.reset();
      cb(take);
    }

    static size_t exactness(const PendingRead &p, size_t avail) {
      return p.exact ? (avail >= p.want ? p.want : 0)
                     : std::min(avail, p.want);
    }

    std::optional<PendingRead> pending_;
    std::deque<uint8_t> incoming_;
    PipeEnd *peer_ = nullptr;
    bool initiator_;
  };

  struct Fixture {
    std::shared_ptr<ManualSchedulerBackend> backend =
        std::make_shared<ManualSchedulerBackend>();
    std::shared_ptr<SchedulerImpl> scheduler =
        std::make_shared<SchedulerImpl>(backend,
                                        libp2p::basic::Scheduler::Config{});

    /// drains ALL scheduled deferrals (dialer_test shift idiom)
    void drain() {
      while (!backend->empty()) {
        backend->shift(std::chrono::milliseconds(1));
      }
    }
  };

  std::shared_ptr<const Psk> makePsk(const std::vector<uint8_t> &bytes) {
    auto res = Psk::fromRawBytes(bytes);
    assert(res);
    return std::shared_ptr<const Psk>(new Psk(std::move(res.value())));
  }

  std::vector<uint8_t> makePattern(size_t n) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) {
      v[i] = static_cast<uint8_t>((i * 31 + 7) & 0xff);
    }
    return v;
  }
}  // namespace

/**
 * @given two PnetProtectedConnections over a byte pipe with the same PSK
 * @when a multi-block payload is written A→B and a different one B→A
 * @then both directions deliver the exact plaintext (two independent
 *        per-direction nonce exchanges happened transparently)
 */
TEST(PnetProtectedConnectionTest, RoundTripSamePskBothDirections) {
  Fixture fx;
  auto end_a = std::make_shared<PipeEnd>(true);
  auto end_b = std::make_shared<PipeEnd>(false);
  end_a->setPeer(end_b.get());
  end_b->setPeer(end_a.get());
  auto psk = makePsk(kPskABytes);

  auto prot_a = std::make_shared<PnetProtectedConnection>(end_a, psk, fx.scheduler);
  auto prot_b = std::make_shared<PnetProtectedConnection>(end_b, psk, fx.scheduler);

  const auto payload_ab = makePattern(200);
  const auto payload_ba = makePattern(150);

  // A → B
  std::vector<uint8_t> got_b(200, 0);
  bool got_b_cb = false;
  prot_b->read(got_b, 200, [&](libp2p::outcome::result<size_t> r) {
    ASSERT_TRUE(r);
    got_b_cb = true;
  });
  prot_a->write(payload_ab, payload_ab.size(), [](auto) {});
  fx.drain();
  ASSERT_TRUE(got_b_cb);
  ASSERT_EQ(got_b, payload_ab);

  // B → A (independent direction, second nonce pair)
  std::vector<uint8_t> got_a(150, 0);
  bool got_a_cb = false;
  prot_a->read(got_a, 150, [&](libp2p::outcome::result<size_t> r) {
    ASSERT_TRUE(r);
    got_a_cb = true;
  });
  prot_b->write(payload_ba, payload_ba.size(), [](auto) {});
  fx.drain();
  ASSERT_TRUE(got_a_cb);
  ASSERT_EQ(got_a, payload_ba);
}

/**
 * @given the raw wire bytes captured on the pipe
 * @when inspected after a protected write
 * @then the first 24 bytes are the cleartext nonce, and the bytes right
 *        after it are NOT the plaintext — a plaintext negotiation would
 *        start with the "/multistream/1.0.0/" header prefix
 */
TEST(PnetProtectedConnectionTest, NonceFirstOnWireNothingElseCleartext) {
  Fixture fx;
  auto end_a = std::make_shared<PipeEnd>(true);
  auto end_b = std::make_shared<PipeEnd>(false);
  end_a->setPeer(end_b.get());
  end_b->setPeer(end_a.get());

  // plaintext multistream prefix a naive negotiation would leak
  const std::string kMultistreamPrefix = "/multistream/1.0.0/";

  auto prot_a = std::make_shared<PnetProtectedConnection>(
      end_a, makePsk(kPskABytes), fx.scheduler);
  auto prot_b = std::make_shared<PnetProtectedConnection>(
      end_b, makePsk(kPskABytes), fx.scheduler);

  // prime B's read direction so both nonce exchanges occur in the capture
  std::vector<uint8_t> sink(200, 0);
  bool read_done = false;
  prot_b->read(sink, 200, [&](auto) { read_done = true; });

  const auto payload = makePattern(200);
  prot_a->write(payload, payload.size(), [](auto) {});
  fx.drain();
  ASSERT_TRUE(read_done);

  const auto &wire = end_a->written_on_wire;
  ASSERT_GE(wire.size(), 24u + 200u);
  // bytes 24..24+len(prefix) must not equal the plaintext multistream header
  const auto after_nonce =
      std::vector<uint8_t>(wire.begin() + 24, wire.begin() + 24 + payload.size());
  ASSERT_NE(after_nonce, payload);
  std::vector<uint8_t> prefix_bytes(kMultistreamPrefix.begin(),
                                    kMultistreamPrefix.end());
  const auto wire_prefix =
      std::vector<uint8_t>(wire.begin() + 24,
                           wire.begin() + 24 + prefix_bytes.size());
  ASSERT_NE(wire_prefix, prefix_bytes);
}

/**
 * @given A with psk1 and B with psk2 over a pipe
 * @when A writes a known plaintext
 * @then B's decryption output differs from the plaintext — garbage, so
 *        multiselect can never succeed (PNET-03)
 */
TEST(PnetProtectedConnectionTest, MismatchedPskDecryptsGarbage) {
  Fixture fx;
  auto end_a = std::make_shared<PipeEnd>(true);
  auto end_b = std::make_shared<PipeEnd>(false);
  end_a->setPeer(end_b.get());
  end_b->setPeer(end_a.get());

  auto prot_a = std::make_shared<PnetProtectedConnection>(
      end_a, makePsk(kPskABytes), fx.scheduler);
  auto prot_b = std::make_shared<PnetProtectedConnection>(
      end_b, makePsk(kPskBBytes), fx.scheduler);

  const auto payload = makePattern(100);
  std::vector<uint8_t> got(100, 0);
  bool read_done = false;
  prot_b->read(got, 100, [&](auto) { read_done = true; });
  prot_a->write(payload, payload.size(), [](auto) {});
  fx.drain();
  ASSERT_TRUE(read_done);
  ASSERT_NE(got, payload);  // garbage, not the plaintext
}

/**
 * @given chunked writes and differently-chunked reads
 * @when 200+ bytes flow in one direction
 * @then keystream positions never desynchronize — exact plaintext despite
 *        unequal partitions (Pitfall 1 regression)
 */
TEST(PnetProtectedConnectionTest, ChunkStormUnequalPartitions) {
  Fixture fx;
  auto end_a = std::make_shared<PipeEnd>(true);
  auto end_b = std::make_shared<PipeEnd>(false);
  end_a->setPeer(end_b.get());
  end_b->setPeer(end_a.get());

  auto prot_a = std::make_shared<PnetProtectedConnection>(
      end_a, makePsk(kPskABytes), fx.scheduler);
  auto prot_b = std::make_shared<PnetProtectedConnection>(
      end_b, makePsk(kPskABytes), fx.scheduler);

  const auto payload = makePattern(200);
  // write partition: 1, 3, 64, 7, 100, 25
  const size_t write_parts[] = {1, 3, 64, 7, 100, 25};
  size_t off = 0;
  for (size_t n : write_parts) {
    prot_a->writeSome(
        gsl::span<const uint8_t>(payload).subspan(off, n), n, [](auto) {});
    off += n;
  }
  fx.drain();
  ASSERT_EQ(off, 200u);

  // read partition (different): readSome(5) then readSome(10) then exact rest
  std::vector<uint8_t> got(200, 0);
  size_t have = 0;
  bool done = false;
  auto read_step = [&](size_t n, bool exact) {
    prot_b->readSome(gsl::span<uint8_t>(got).subspan(have, n), n,
                     [&](libp2p::outcome::result<size_t> r) {
                       ASSERT_TRUE(r);
                       have += r.value();
                       if (have == 200) done = true;
                     });
    fx.drain();
  };
  // sequential reads complete synchronously on the pipe
  for (auto [n, exact] : std::initializer_list<std::pair<size_t, bool>>{
           {5, false}, {10, false}, {185, true}}) {
    (void)exact;
    read_step(n, exact);
  }
  ASSERT_TRUE(done);
  ASSERT_EQ(got, payload);
}

/**
 * @given all pnet callbacks routed through the scheduler
 * @when a write completes
 * @then the user callback fires only after the scheduler drains — never
 *        inline from the inner write
 */
TEST(PnetProtectedConnectionTest, CompletionDeferredThroughScheduler) {
  Fixture fx;
  auto end_a = std::make_shared<PipeEnd>(true);
  auto end_b = std::make_shared<PipeEnd>(false);
  end_a->setPeer(end_b.get());
  end_b->setPeer(end_a.get());

  auto prot_a = std::make_shared<PnetProtectedConnection>(
      end_a, makePsk(kPskABytes), fx.scheduler);

  bool fired = false;
  const auto payload = makePattern(50);
  prot_a->write(payload, payload.size(), [&](auto) { fired = true; });
  // PipeEnd completes synchronously; the defer* layer must still hold the
  // callback until the scheduler drains
  ASSERT_FALSE(fired);
  fx.drain();
  ASSERT_TRUE(fired);
}

/** close() on the wrapper delegates to the inner connection */
TEST(PnetProtectedConnectionTest, Delegation) {
  Fixture fx;
  auto end_a = std::make_shared<PipeEnd>(true);
  auto end_b = std::make_shared<PipeEnd>(false);
  end_a->setPeer(end_b.get());
  end_b->setPeer(end_a.get());

  auto prot = std::make_shared<PnetProtectedConnection>(
      end_a, makePsk(kPskABytes), fx.scheduler);
  ASSERT_FALSE(prot->isClosed());
  ASSERT_TRUE(prot->isInitiator());
  ASSERT_TRUE(prot->close());  // outcome success (delegates to inner)
}

/**
 * @given an inner connection whose first read errors
 * @when the protected read path runs
 * @then the callback receives PNET_NONCE_READ_FAILED (deferred)
 */
TEST(PnetProtectedConnectionTest, NonceReadFailurePath) {
  // erroring inner end: fails every read
  class FailingEnd : public PipeEnd {
   public:
    FailingEnd() : PipeEnd(true) {}
    void read(gsl::span<uint8_t>, size_t, ReadCallbackFunc cb) override {
      cb(std::errc::connection_reset);
    }
    void readSome(gsl::span<uint8_t>, size_t, ReadCallbackFunc cb) override {
      cb(std::errc::connection_reset);
    }
  };

  Fixture fx;
  auto failing = std::make_shared<FailingEnd>();
  auto prot = std::make_shared<PnetProtectedConnection>(
      failing, makePsk(kPskABytes), fx.scheduler);

  std::vector<uint8_t> buf(10, 0);
  std::optional<libp2p::outcome::result<size_t>> result;
  bool fired = false;
  prot->read(buf, 10, [&](libp2p::outcome::result<size_t> r) {
    result = r;
    fired = true;
  });
  fx.drain();
  ASSERT_TRUE(fired);
  ASSERT_FALSE(result.value());
  ASSERT_EQ(result.value().error(), PnetError::PNET_NONCE_READ_FAILED);
}
