# Testing Patterns

**Analysis Date:** 2026-08-26

## Test Framework

**Runner:**
- GoogleTest (gtest) + GoogleMock (gmock), pulled via Hunter (`cmake/Hunter/init.cmake`) and linked as `GTest::gtest`, `GTest::main`, `GMock::main`.
- Config/build wiring: `test/CMakeLists.txt` (root of test tree) plus a custom CMake helper `addtest()` in `cmake/functions.cmake`.

**Assertion Library:**
- Native gtest/gmock assertions: `ASSERT_*` / `EXPECT_*`, plus project-defined `EXPECT_OUTCOME_TRUE*` / `EXPECT_OUTCOME_FALSE*` macros (`test/testutil/outcome.hpp`) for asserting on `outcome::result<T>` values without exceptions.

**Run Commands:**
```bash
cmake -B build -DTESTING=ON              # tests are built by default (TESTING option, ON)
cmake --build build
ctest --test-dir build                   # runs all tests registered via add_test()
```
Test binaries are emitted to `${CMAKE_BINARY_DIR}/test_bin`. There is no coverage target invoked from this repo's own scripts beyond the `COVERAGE` CMake option (gcov-based) and `codecov.yml` for CI upload.

## Test File Organization

**Location:**
- Fully separate test tree under `test/`, mirroring `include/libp2p/`/`src/` module layout:
  - `test/libp2p/<module>/<name>_test.cpp` — unit tests (e.g. `test/libp2p/crypto/hmac_test.cpp`, `test/libp2p/muxer/...`).
  - `test/acceptance/p2p/...` — higher-level integration/acceptance tests exercising full `Host` behavior (`test/acceptance/p2p/host/basic_host_test.cpp`, `host_integration_test.cpp`).
  - `test/mock/libp2p/<module>/<name>_mock.hpp` — GMock doubles for every public interface, mirroring `include/libp2p/<module>/`.
  - `test/testutil/` — shared test helpers, fixtures, macros (not test cases themselves).
  - `test/deps/` — sanity tests for third-party dependency wiring (e.g. `di_test.cpp` for Boost.DI).

**Naming:**
- `<subject>_test.cpp` for test files; `TEST_F(<SubjectTest>, <BehaviorName>)` (PascalCase test-case class ending in `Test`, PascalCase behavior name describing the scenario, e.g. `BasicHostTest, GetPeerInfo`).

**Structure:**
```
test/
├── acceptance/p2p/host/          # end-to-end Host scenarios
├── libp2p/<module>/               # unit tests per src module (crypto, muxer, network, peer, protocol, security, storage, transport, ...)
├── mock/libp2p/<module>/          # GMock doubles per interface
├── testutil/                      # shared fixtures, macros, generators
└── deps/                          # dependency sanity checks
```
Each subdirectory has its own `CMakeLists.txt` calling `addtest(<name> <sources>)`; new test files must be registered there.

## Test Structure

**Suite Organization** (fixture-based, from `test/acceptance/p2p/host/basic_host_test.cpp`):
```cpp
struct BasicHostTest : public ::testing::Test {
  std::shared_ptr<connection::StreamMock> stream =
      std::make_shared<connection::StreamMock>();
  std::shared_ptr<peer::IdentityManagerMock> idmgr =
      std::make_shared<peer::IdentityManagerMock>();
  // ... other mocked collaborators, constructed inline as member initializers

  std::unique_ptr<Host> host = std::make_unique<host::BasicHost>(
      idmgr, std::make_unique<network::NetworkMock>(), ...);

  peer::PeerId id = "1"_peerid;
  multi::Multiaddress ma1 = "/ip4/1.3.3.7/udp/1"_multiaddr;
};

/**
 * @given default host
 * @when getId is called
 * @then peer's id is returned
 */
TEST_F(BasicHostTest, GetId) {
  EXPECT_CALL(*idmgr, getId()).WillOnce(ReturnRef(id));
  auto actual = host->getId();
  ASSERT_EQ(id, actual);
}
```

**Patterns:**
- Prefer `TEST_F` fixtures over bare `TEST` when any shared setup/mocks are needed; fixture members are constructed via in-class default initializers rather than `SetUp()` where possible (see `BasicHostTest`), but `SetUp()` overrides are used for non-trivial setup (e.g. `HmacTest::SetUp()` building a shared message buffer).
- Every non-trivial `TEST`/`TEST_F` is preceded by a `@given/@when/@then` Doxygen comment block — this is the dominant, consistently-applied documentation convention; follow it for all new tests.
- Test literal suffixes: `"..."_unhex`, `"1"_peerid`, `"/ip4/.../udp/1"_multiaddr` — custom `libp2p::common` / test literal operators used throughout to build domain values tersely.

## Mocking

**Framework:** GoogleMock, with hand-written mock classes (not auto-generated) at `test/mock/libp2p/<module>/<name>_mock.hpp`, one per public interface.

**Patterns:**
```cpp
namespace libp2p::connection {
  class StreamMock : public Stream {
   public:
    ~StreamMock() override = default;
    StreamMock() = default;
    explicit StreamMock(uint8_t id) : stream_id{id} {}
    uint8_t stream_id = 137;   // exposed field purely to ease assertions

    MOCK_CONST_METHOD0(isClosed, bool(void));
    MOCK_METHOD3(read, void(gsl::span<uint8_t>, size_t, Reader::ReadCallbackFunc));
    MOCK_CONST_METHOD0(isInitiator, outcome::result<bool>());
    // ...
  };
}
```
- Uses legacy `MOCK_METHODn` / `MOCK_CONST_METHODn` macros (not the newer `MOCK_METHOD(...)` single-macro form) throughout the codebase — match this style for new mocks.
- Mocks implement the real abstract interface directly (`class StreamMock : public Stream`), so they're substitutable via `std::shared_ptr<Interface>` in production constructors — enabling constructor-injection-based unit testing without a DI container in tests.
- `test/testutil/gmock_actions.hpp` provides custom gmock Actions (e.g. `Arg2CallbackWithArg`) for invoking callback-style arguments synchronously inside `EXPECT_CALL(...).WillOnce(...)`.
- `EXPECT_CALL` with `_` (`::testing::_` wildcard matcher), `Return`, `ReturnRef`, `.Times(n)` / `.WillRepeatedly(...)` are the standard verification idioms.

**What to Mock:**
- All collaborators reached through an abstract interface (`Network`, `Dialer`, `Listener`, `PeerRepository`, `AddressRepository`, `IdentityManager`, `Stream`, etc.) — anything injected via constructor.

**What NOT to Mock:**
- Concrete value types (`PeerId`, `Multiaddress`, `PeerInfo`) and the class under test itself are constructed for real, not mocked.

## Fixtures and Factories

**Test Data:**
- Inline member-initializer construction of value objects using literal operators, e.g.:
```cpp
peer::PeerId id = "1"_peerid;
multi::Multiaddress ma1 = "/ip4/1.3.3.7/udp/1"_multiaddr;
```
- `test/testutil/ma_generator.hpp` and `test/testutil/libp2p/peer.hpp` provide reusable generators for multiaddresses/peer identities across suites.
- `test/testutil/async/` provides fake/deterministic clock implementations (`clock.hpp`, `impl/clock_impl.cpp`) for testing time-dependent scheduler logic without real delays.

**Location:** `test/testutil/` (shared across all test suites); module-specific fixtures live alongside the tests that use them in `test/libp2p/<module>/`.

## Coverage

**Requirements:** No hard threshold enforced locally; `codecov.yml` configures Codecov reporting in CI, and CMake option `COVERAGE` (default OFF) enables gcov instrumentation.

**View Coverage:**
```bash
cmake -B build -DTESTING=ON -DCOVERAGE=ON
cmake --build build
ctest --test-dir build
# coverage data collected via gcov/lcov tooling driven by CI (see docker-compose.yml / housekeeping/ for CI scripts)
```

## Test Types

**Unit Tests:**
- Bulk of `test/libp2p/<module>/` — isolate one class using GMock doubles for all collaborators (see Mocking above). Cover crypto primitives, connection/muxer framing logic, peer/address repositories, protocol implementations (Kademlia, protocol muxer), storage, and transport.

**Integration/Acceptance Tests:**
- `test/acceptance/p2p/host/` — wires together closer-to-real components (e.g. `host_integration_test.cpp`) to validate cross-component behavior (dialing, stream negotiation) rather than a single class in isolation.

**E2E Tests:** Not present as a distinct category; acceptance tests under `test/acceptance/` serve this role at the library level (no browser/network-process E2E harness).

## Common Patterns

**Async/Callback Testing:**
```cpp
bool executed = false;
host->newStream(pinfo, {protocol}, [&](auto &&result) {
  EXPECT_OUTCOME_TRUE(stream, result);
  (void)stream;
  executed = true;
});
ASSERT_TRUE(executed);
```
Async APIs are exercised synchronously in tests by having mocks invoke the callback immediately (via custom gmock Actions like `Arg2CallbackWithArg`), then asserting a captured `bool executed` flag plus outcome-macro checks inside the callback body.

**Outcome/Error Testing:**
```cpp
EXPECT_OUTCOME_TRUE(stream, result);          // asserts result is success, binds .value() to `stream`
EXPECT_OUTCOME_FALSE(err, result);            // asserts result is failure, binds .error() to `err`
```
Defined in `test/testutil/outcome.hpp`; always prefer these macros over manually calling `.value()`/`.error()` when asserting on `outcome::result<T>` in tests, since they emit the failing line number and error message on assertion failure.

---

*Testing analysis: 2026-08-26*
