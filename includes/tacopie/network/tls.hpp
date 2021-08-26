// MIT License
//
// Copyright (c) 2016-2017 Simon Ninon <simon.ninon@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#include <tacopie/utils/typedefs.hpp>

#ifdef _WIN32
#include <cstdint>
#include <string>
#include <vector>
#include <sspi.h>
#include <schannel.h>
#include <wchar.h>
#endif

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Crypt32.Lib")


namespace tacopie {

//!
//! used to force poll to wake up
//! simply make poll watch for read events on one side of the pipe and write to the other side
//!
class tls {
public:
  //! ctor
  tls(void);
  //! dtor
  ~tls(void);

  public:

  //!
  //! connect
  //!
  void
  establish_connection(const fd_t& socket, const std::string& host);
  
  //!
  //! Encrypt and send data (synchronous)
  //!
  //! \param socket
  //! \param unencrypted data
  //! \return Returns amount of unencrypted data sent (caller does not know about encrypted size)
  //!
  std::size_t
  send_encrypted(const fd_t& socket, const std::vector<char>& unencrypted_data);
  
  //!
  //! Receive data from the socket until able to decrypt completely (synchronous).
  //! "Completely" here means at least a single encryptable block, may be more.
  //!
  //! \param socket
  //! \return Returns vector with decrypted data. Size is as large as needed. You need to handle this.
  //!
  std::vector<char>
  recv_decrypt(const fd_t& socket);

  //!
  //! is encryption active
  //!
  bool
  is_encryption_active() { return m_encryption_active; }

  private:

#ifdef _WIN32
  CredHandle m_h_credentials;
  CtxtHandle m_ph_context;
  SecPkgContext_StreamSizes m_stream_sizes;
  bool m_encryption_active;

  void get_schannel_credentials();
  void handshake_loop(const fd_t& socket, const std::string &host);
  std::string get_sspi_result_string(SECURITY_STATUS SecurityStatus);

#else
#endif /* _WIN32 */
};

} // namespace tacopie
