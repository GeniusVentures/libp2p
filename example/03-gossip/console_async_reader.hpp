/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBP2P_CONSOLE_ASYNC_READER_HPP
#define LIBP2P_CONSOLE_ASYNC_READER_HPP

#include <string>
#include <functional>

#include <boost/asio.hpp>

#ifdef _WIN32
#include <boost/asio/windows/stream_handle.hpp>
#include <io.h>  // For _get_osfhandle
#else
#include <boost/asio/posix/stream_descriptor.hpp>
#include <unistd.h>  // For STDIN_FILENO and dup
#endif

namespace libp2p::protocol::example::utility {

  /// Asio-based asynchronous line reader from stdin
  class ConsoleAsyncReader {
   public:
    /// lines read from the console come into this callback
    using Handler = std::function<void(const std::string &)>;

    /// starts the reader
    ConsoleAsyncReader(boost::asio::io_context &io, Handler handler);

    /// stops the reader: no more callbacks after this call
    void stop();

   private:
    /// begins read operation
    void read();

    /// read callback from asio
    void onRead(const boost::system::error_code &e, std::size_t size);

#ifdef _WIN32
    boost::asio::windows::stream_handle in_;
#else
    boost::asio::posix::stream_descriptor in_;
#endif
    boost::asio::streambuf input_;
    std::string line_;
    Handler handler_;
    bool stopped_ = false;
  };

} //namespace libp2p::protocol::example::utility

#endif  // LIBP2P_CONSOLE_ASYNC_READER_HPP
