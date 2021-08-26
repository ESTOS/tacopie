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

//! guard for bulk content integration depending on how user integrates the library
#ifdef _WIN32

#include <tacopie/network/tls.hpp>
#include <tacopie/utils/error.hpp>

#include <winsock2.h>

#include <tacopie/utils/typedefs.hpp>
#include <sstream>
#include <string>
#include <iomanip>
#include <tacopie/utils/logger.hpp>

// There is no handling of connection loss or renegotiate here. It is left to the above
// wrapper to initialte a reconnect in such cases.

namespace tacopie {

//!
//! ctor & dtor
//!
tls::tls(void)
: m_encryption_active(false) {
  __TACOPIE_LOG(debug, "tls constructed");  
  }

tls::~tls(void) {
}

//!
//! establish a secure connection
//!
void
tls::establish_connection(const fd_t &socket, const std::string& host) {
  get_schannel_credentials();
  handshake_loop(socket, host);
  m_encryption_active = true;
}

//!
//! get schannel credentials
//!
void
tls::get_schannel_credentials() {
  TimeStamp lifetime;
  SCHANNEL_CRED credentials_data;

  ZeroMemory(&credentials_data, sizeof(credentials_data));
  credentials_data.dwVersion = SCHANNEL_CRED_VERSION;
  // opportunity to restrict used protocols on client side. Suggest to use this only for
  // tests and implement needed restrictions on server.
  // credData.grbitEnabledProtocols = SP_PROT_TLS1;

  SECURITY_STATUS security_status = AcquireCredentialsHandle( //gets the credentials necessary to make use of the ssp
    NULL,                                                    //default principle
    UNISP_NAME,                                              //name of schannel ssp
    SECPKG_CRED_OUTBOUND,                                    //states that the client will use the returned credential
    NULL,                                                    //use current logon id instead of searching for previous one
    &credentials_data,                                       //protocol specific data
    NULL,                                                    //default
    NULL,                                                    //default
    &m_h_credentials,                                         //where the handle will be stored
    &lifetime                                                //stores the time limit of the credential
  );

  if (security_status != SEC_E_OK) {
    __TACOPIE_THROW(error, std::string("AcquireCredentialsHandle result: ") + get_sspi_result_string(security_status));
  }
  else {
    __TACOPIE_LOG(debug, "credentials acquired successfully");

  }
}

void
tls::handshake_loop(const fd_t& socket, const std::string& host) {

  TimeStamp lifetime;
  SecBufferDesc out_buffer_desc;
  SecBuffer out_buffer[1];
  SecBufferDesc in_buffer_desc;
  SecBuffer in_buffer[2];
  ULONG ul_context_attributes;
  DWORD flags;

  out_buffer_desc.ulVersion = SECBUFFER_VERSION;
  out_buffer_desc.cBuffers  = 1;
  out_buffer_desc.pBuffers  = out_buffer;

  out_buffer[0].cbBuffer   = 0;               //	size(cbBuff) is 0 and data(pvBuff) is null because ISC_ALLOC_MEM was
  out_buffer[0].BufferType = SECBUFFER_TOKEN; //	was specified and will automatically create memory and fill the buffer
  out_buffer[0].pvBuffer   = NULL;

  int wchars_num = MultiByteToWideChar(CP_UTF8, 0, host.c_str(), -1, NULL, 0);
  std::vector<wchar_t> whost(wchars_num);
  MultiByteToWideChar(CP_UTF8, 0, host.c_str(), -1, whost.data(), wchars_num);

  // Meaning of flags and error codes explained here: https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-initializesecuritycontextw
  flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_STREAM | ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR;

  SECURITY_STATUS security_status = InitializeSecurityContext(
    &m_h_credentials,      // credentials acquired by acquireCredentialsHandle
    NULL,                 // in the first call this is NULL, afterwards use hcText parameter variable
    whost.data(),         // name of the server
    flags,                // bit flags that state how the security context will function
    0,                    // this argument is reserved and left as 0
    SECURITY_NATIVE_DREP, // how the data is represented. In schannel this argument is not used and set to 0
    NULL,                 // this is the buffer that will be received from the server. On the first call this is NULL
    0,                    // reserved and set to 0
    &m_ph_context,         // receives the context handle. With Schannel, after the first call, this must be NULL and
                          // arg2 must take phContext
    &out_buffer_desc,       // buffer where the token will be stored. This will be sent to the server later
    &ul_context_attributes, // this is where the set of bit flags will be received. These flags indicate the attributes of the context
    &lifetime);

  if (security_status != SEC_I_CONTINUE_NEEDED) {
    __TACOPIE_THROW(error, get_sspi_result_string(security_status));
  }

  bool process_extra_data = false;
  int bytes_received_count = 0;
  char* pc_token = NULL;
  std::vector<char> buffer(4000);

  while (security_status != SEC_E_OK) {
    if (security_status == SEC_I_CONTINUE_NEEDED && !process_extra_data) {
      if (out_buffer[0].cbBuffer > 0) {
        pc_token = static_cast<char*>(out_buffer[0].pvBuffer);
        ::send(socket, pc_token, out_buffer[0].cbBuffer, 0);
        FreeContextBuffer(out_buffer[0].pvBuffer);
      }
      bytes_received_count = ::recv(socket, buffer.data(), static_cast<unsigned int> (buffer.size()), 0);
    }
    else if (security_status == SEC_E_INCOMPLETE_MESSAGE) {
      if (in_buffer[1].BufferType == SECBUFFER_MISSING) {
        int missing_data_count = in_buffer[1].cbBuffer;
        __TACOPIE_LOG(info, std::string("secbuffer_missing: " + missing_data_count));
        bytes_received_count = ::recv(socket, buffer.data(), missing_data_count, 0);
      }
    }

    in_buffer_desc.cBuffers  = 2;
    in_buffer_desc.pBuffers  = in_buffer;
    in_buffer_desc.ulVersion = SECBUFFER_VERSION;

    in_buffer[0].cbBuffer   = bytes_received_count;
    in_buffer[0].pvBuffer   = buffer.data();
    in_buffer[0].BufferType = SECBUFFER_TOKEN;

    in_buffer[1].cbBuffer   = 0;
    in_buffer[1].pvBuffer   = NULL;
    in_buffer[1].BufferType = SECBUFFER_EMPTY;

    out_buffer_desc.cBuffers  = 1;
    out_buffer_desc.pBuffers  = out_buffer;
    out_buffer_desc.ulVersion = SECBUFFER_VERSION;

    out_buffer[0].cbBuffer   = 0;
    out_buffer[0].pvBuffer   = NULL;
    out_buffer[0].BufferType = SECBUFFER_VERSION;

    // https: //docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-initializesecuritycontextw
    security_status = InitializeSecurityContext(
    &m_h_credentials,
    &m_ph_context,
    NULL,
    flags,
    0,
    SECURITY_NATIVE_DREP,
    &in_buffer_desc,
    0,
    NULL,
    &out_buffer_desc,
    &ul_context_attributes,
    &lifetime);

    process_extra_data = false;

    // This comment from curl is the best description I found of what can happen here with SECBUFFER_EXTRA:
    // There are two cases where we could be getting extra data here:
    //  1) If we're renegotiating a connection and the handshake is already
    //  complete (from the server perspective), it can [contain] encrypted app data
    //  (not handshake data) in an extra buffer at this point.
    //  2) (sspi_status == SEC_I_CONTINUE_NEEDED) We are negotiating a
    //  connection and this extra data is part of the handshake.
    //  We should process the data immediately; waiting for the socket to
    //  be ready may fail since the server is done sending handshake data.
    switch (security_status) {

    case SEC_I_CONTINUE_NEEDED:
      if (in_buffer[1].BufferType == SECBUFFER_EXTRA) {
        __TACOPIE_LOG(info, std::string("CONTINUE_NEEDED: Extra data in in_buffer"));
        // shift exta bytes to the beginning of the input buffer
        if (in_buffer[1].cbBuffer > static_cast<unsigned long long>(bytes_received_count))
          __TACOPIE_THROW(error, "part of buffer larger than whole");
        memmove(buffer.data(), buffer.data() + (static_cast<unsigned long long>(bytes_received_count) - in_buffer[1].cbBuffer), in_buffer[1].cbBuffer);
        bytes_received_count = in_buffer[1].cbBuffer;
        process_extra_data = true;
      }
      break;

    case SEC_E_OK:
      if (out_buffer[0].cbBuffer > 0) {
        __TACOPIE_LOG(info, std::string("sending leftover bytes in output buffer"));
        pc_token = static_cast<char*>(out_buffer[0].pvBuffer);
        ::send(socket, pc_token, out_buffer[0].cbBuffer, 0);
        FreeContextBuffer(out_buffer[0].pvBuffer);
      }
      if (in_buffer[1].BufferType == SECBUFFER_EXTRA) {
        __TACOPIE_LOG(info, std::string("SEC_E_OK: Extra data in in_buffer"));
        // These bytes need to be decrypted [currently not handled]
        __TACOPIE_LOG(warn, std::string("Extra bytes to be decrypted") + std::to_string(in_buffer[1].cbBuffer));
      }
      break;

    default:
      __TACOPIE_THROW(error, get_sspi_result_string(security_status));
      break;
    }
  } // while !SEC_E_OK

  __TACOPIE_LOG(info, "secure connection successfully established");
}

//!
//! send encrypted data
//!
std::size_t
tls::send_encrypted(const fd_t& socket, const std::vector<char>& unencrypted_data) {

  SECURITY_STATUS security_status = QueryContextAttributes(&m_ph_context, SECPKG_ATTR_STREAM_SIZES, &m_stream_sizes);

  if (security_status != SEC_E_OK) {
    __TACOPIE_LOG(warn, std::string("QueryContextAttributes result: ") + get_sspi_result_string(security_status));
  }

  int max_out_size = m_stream_sizes.cbHeader + m_stream_sizes.cbMaximumMessage + m_stream_sizes.cbTrailer;
  std::vector<char> buffer(max_out_size);

  std::size_t unencrypted_bytes_written = 0;

  while (unencrypted_bytes_written < unencrypted_data.size()) {

    std::size_t unencrypted_bytes_left = unencrypted_data.size() - unencrypted_bytes_written;
    std::size_t current_unencrypted_chunk = unencrypted_bytes_left > m_stream_sizes.cbMaximumMessage ? m_stream_sizes.cbMaximumMessage : unencrypted_bytes_left;
    if (unencrypted_bytes_left > m_stream_sizes.cbMaximumMessage)
      unencrypted_bytes_left += 0;

    //copy the unencrypted data just after the header bytes to the buffer
    memcpy(buffer.data() + m_stream_sizes.cbHeader, unencrypted_data.data() + unencrypted_bytes_written, current_unencrypted_chunk);

    SecBufferDesc message_buffer;
    SecBuffer buffers[4];

    message_buffer.cBuffers  = 4;
    message_buffer.pBuffers  = buffers;
    message_buffer.ulVersion = SECBUFFER_VERSION;

    buffers[0].cbBuffer   = m_stream_sizes.cbHeader;
    buffers[0].pvBuffer   = buffer.data();
    buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

    buffers[1].cbBuffer   = static_cast<unsigned long>(current_unencrypted_chunk);
    buffers[1].pvBuffer   = buffer.data() + m_stream_sizes.cbHeader;
    buffers[1].BufferType = SECBUFFER_DATA;

    buffers[2].cbBuffer   = m_stream_sizes.cbTrailer;
    buffers[2].pvBuffer   = buffer.data() + m_stream_sizes.cbHeader + static_cast<unsigned long>(current_unencrypted_chunk);
    buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

    buffers[3].cbBuffer   = 0;
    buffers[3].pvBuffer   = NULL;
    buffers[3].BufferType = SECBUFFER_EMPTY;

    // https://docs.microsoft.com/en-us/windows/win32/secauthn/encryptmessage--schannel
    security_status = EncryptMessage(&m_ph_context, 0, &message_buffer, 0);
    if (security_status != SEC_E_OK) {
      __TACOPIE_THROW(error, std::string("EncryptMessage result: ") + get_sspi_result_string(security_status));
    }

    int encrypted_size = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;

    ssize_t send_result = ::send(socket, buffer.data(), encrypted_size, 0);
    if (send_result == SOCKET_ERROR)
      return send_result;

    unencrypted_bytes_written += current_unencrypted_chunk;
  } // while bytes left to send

  return unencrypted_bytes_written;
}

//!
//! receive and decrypt
//!
std::vector<char>
tls::recv_decrypt(const fd_t& socket) {

  int encrypted_bytes = 0;
  int decrypted_bytes = 0;
  const std::size_t buffer_increment_size = 0x1000;
  std::vector<char> encrypted_data;
  std::vector<char> decrypted_data;
  SECURITY_STATUS security_status = SEC_E_OK;
  SecBufferDesc buffer_desc;
  SecBuffer sec_buffer[4];

  // read more data until able to decrypt or decryptable data block not complete (in
  // case part of next block has already been received)
  while (decrypted_bytes == 0 || security_status == SEC_E_INCOMPLETE_MESSAGE) {
    encrypted_data.resize(encrypted_bytes + buffer_increment_size); // buffer needs to grow on incomplete messages
    encrypted_bytes += ::recv(socket, const_cast<char*>(encrypted_data.data()) + encrypted_bytes, static_cast<unsigned long>(buffer_increment_size), 0);

    if (encrypted_bytes == SOCKET_ERROR) { __TACOPIE_THROW(error, "recv() failure"); }
    if (encrypted_bytes == 0) { __TACOPIE_THROW(warn, "nothing to read, socket has been closed by remote host"); }

    __TACOPIE_LOG(debug, std::string("encrypted bytes in buffer: ") + std::to_string(encrypted_bytes));
    security_status = SEC_E_OK;

    while (encrypted_bytes != 0 && security_status != SEC_E_INCOMPLETE_MESSAGE) {
      buffer_desc.cBuffers  = 4;
      buffer_desc.pBuffers  = sec_buffer;
      buffer_desc.ulVersion = SECBUFFER_VERSION;

      sec_buffer[0].cbBuffer   = encrypted_bytes;
      sec_buffer[0].pvBuffer   = encrypted_data.data(); // not decrypted in place as documented
      sec_buffer[0].BufferType = SECBUFFER_DATA;

      sec_buffer[1].BufferType = SECBUFFER_EMPTY;
      sec_buffer[2].BufferType = SECBUFFER_EMPTY;
      sec_buffer[3].BufferType = SECBUFFER_EMPTY;

      // https://docs.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--general
      // https://docs.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--schannel
      security_status = DecryptMessage(&m_ph_context, &buffer_desc, 0, NULL);

      switch (security_status) {
      case SEC_E_OK: {
        __TACOPIE_LOG(debug, "data successfully decrypted");

        encrypted_bytes = 0; // all bytes used

        for (int i = 0; i < 4; i++) {
          switch (sec_buffer[i].BufferType) {
          case SECBUFFER_DATA:
            // append decrypted bytes to output buffer. May be 0 bytes according to doc.
            if (sec_buffer[i].cbBuffer) {
              decrypted_data.resize(decrypted_bytes + sec_buffer[i].cbBuffer);
              memcpy(const_cast<char*>(decrypted_data.data()) + decrypted_bytes, sec_buffer[i].pvBuffer, sec_buffer[i].cbBuffer);
              decrypted_bytes += sec_buffer[i].cbBuffer;
              FreeContextBuffer(sec_buffer[i].pvBuffer);
            }
            break;
          case SECBUFFER_EXTRA:
            // When a block has been decrypted, there may be data already read for the next block in the buffer.
            __TACOPIE_LOG(info, std::string("Data for next encryptable block: " + std::to_string(sec_buffer[i].cbBuffer)));
            memmove(const_cast<char*>(encrypted_data.data()), sec_buffer[i].pvBuffer, sec_buffer[i].cbBuffer);
            encrypted_bytes = sec_buffer[i].cbBuffer;
            //FreeContextBuffer(sec_buffer[i].pvBuffer); // triggers exception
            break;
          default:
            break;
          }
        }
        break;
      }

      case SEC_E_DECRYPT_FAILURE:
        for (int i = 0; i < 4; i++) {
          if (sec_buffer[i].BufferType == SECBUFFER_ALERT) {
            __TACOPIE_LOG(warn, std::string("SECBUFFER_ALERT: ") + std::string((char*) sec_buffer[i].pvBuffer));
          }
        }
        __TACOPIE_THROW(warn, std::string("failed to decrypt: ") + get_sspi_result_string(security_status));
        break;

      case SEC_E_INCOMPLETE_MESSAGE:
        // we need to read more data
        __TACOPIE_LOG(debug, get_sspi_result_string(security_status));
        break;

      default:
        __TACOPIE_THROW(warn, get_sspi_result_string(security_status));
      } // switch
    } // while encrypted bytes && security_status != SEC_E_INCOMPLETE_MESSAGE
  } // while decrypted_bytes == 0 || security_status == SEC_E_INCOMPLETE_MESSAGE

  return decrypted_data;
}

std::string
tls::get_sspi_result_string(SECURITY_STATUS security_status) {

  std::stringstream hexval;
  hexval << "0x" << std::setfill('0') << std::setw(8) << std::hex << security_status;
  std::string str_message = hexval.str();

  // https://docs.microsoft.com/en-us/windows/win32/secauthn/sspi-status-codes
  std::pair<SECURITY_STATUS, std::string> security_status_as_string[] {
    {CERT_E_CHAINING, "CERT_E_CHAINING - A certificate chain could not be build to a trusted root authority."},
    {CERT_E_CN_NO_MATCH, "CERT_E_CN_NO_MATCH - The certificate's CN name does not match the passed value."},
    {CERT_E_CRITICAL, "CERT_E_CRITICAL - A certificate contains an unknown extension that is marked 'critical'."},
    {CERT_E_EXPIRED, "CERT_E_EXPIRED - A required certificate is not within its validity period when verifying against the current system clock or the timestamp in the signed file."},
    {CERT_E_INVALID_NAME, "CERT_E_INVALID_NAME - The certificate has an invalid name. The name is not included in the permitted list or is explicitly excluded."},
    {CERT_E_INVALID_POLICY, "CERT_E_INVALID_POLICY - The certificate has invalid policy."},
    {CERT_E_ISSUERCHAINING, "CERT_E_ISSUERCHAINING - A parent of a given certificate in fact did not issue that child certificate."},
    {CERT_E_MALFORMED, "CERT_E_MALFORMED - A certificate is missing or has an empty value for an important field, such as a subject or issuer name."},
    {CERT_E_PATHLENCONST, "CERT_E_PATHLENCONST - A Path length constraint in the certification chain has been violated."},
    {CERT_E_PURPOSE, "CERT_E_PURPOSE - A certificate being used for a purpose other than the ones specified by its CA."},
    {CERT_E_REVOCATION_FAILURE, "CERT_E_REVOCATION_FAILURE - The revocation process could not continue - the certificate(s) could not be checked."},
    {CERT_E_REVOKED, "CERT_E_REVOKED - A certificate was explicitly revoked by its issuer."},
    {CERT_E_ROLE, "CERT_E_ROLE - A certificate that can only be used as an end-entity is being used as a CA or vice versa."},
    {CERT_E_UNTRUSTEDCA, "CERT_E_UNTRUSTEDCA - A certification chain processed correctly, but one of the CA certificates is not trusted by the policy provider."},
    {CERT_E_UNTRUSTEDTESTROOT, "CERT_E_UNTRUSTEDTESTROOT - The certification path terminates with the test root which is not trusted with the current policy settings."},
    {CERT_E_VALIDITYPERIODNESTING, "CERT_E_VALIDITYPERIODNESTING - The validity periods of the certification chain do not nest correctly."},
    {CERT_E_WRONG_USAGE, "CERT_E_WRONG_USAGE - The certificate is not valid for the requested usage."},

    {SEC_E_BUFFER_TOO_SMALL, "SEC_E_BUFFER_TOO_SMALL - The message buffer is too small."},
    {SEC_I_CONTEXT_EXPIRED, "SEC_I_CONTEXT_EXPIRED - The message sender has finished using the connection and has initiated a shutdown."},
    {SEC_I_COMPLETE_AND_CONTINUE, "SEC_I_COMPLETE_AND_CONTINUE - The function completed successfully, but the application must call both CompleteAuthToken and then either InitializeSecurityContext or AcceptSecurityContext again to complete the context."},
    {SEC_I_COMPLETE_NEEDED, "SEC_I_COMPLETE_NEEDED - The function completed successfully, but you must call the CompleteAuthToken function on the final message."},
    {SEC_I_CONTINUE_NEEDED, "SEC_I_CONTINUE_NEEDED - The function completed successfully, but you must call this function again to complete the context."},
    {SEC_E_DECRYPT_FAILURE, "SEC_E_DECRYPT_FAILURE - The specified data could not be decrypted."},
    {SEC_E_ENCRYPT_FAILURE, "SEC_E_ENCRYPT_FAILURE - The specified data could not be encrypted."},
    {SEC_I_INCOMPLETE_CREDENTIALS, "SEC_I_INCOMPLETE_CREDENTIALS - The credentials supplied were not complete and could not be verified. Additional information can be returned from the context."},
    {SEC_E_INCOMPLETE_MESSAGE, "SEC_E_INCOMPLETE_MESSAGE - The data in the input buffer is incomplete. The application needs to read more data from the server and call DecryptMessage (General) again."},
    {SEC_E_INVALID_HANDLE, "SEC_E_INVALID_HANDLE - A context handle that is not valid was specified in the phContext parameter."},
    {SEC_E_INVALID_TOKEN, "SEC_E_INVALID_TOKEN - The buffers are of the wrong type or no buffer of type SECBUFFER_DATA was found."},
    {SEC_E_INSUFFICIENT_MEMORY, "SEC_E_INSUFFICIENT_MEMORY - Not enough memory is available to complete the request."},
    {SEC_E_INTERNAL_ERROR, "SEC_E_INTERNAL_ERROR - An error occurred that did not map to an SSPI error code."},
    {SEC_E_MESSAGE_ALTERED, "SEC_E_MESSAGE_ALTERED - The message has been altered."},
    {SEC_E_NO_AUTHENTICATING_AUTHORITY, "SEC_E_NO_AUTHENTICATING_AUTHORITY - No authority could be contacted for authentication."},
    {SEC_E_NO_CREDENTIALS, "SEC_E_NO_CREDENTIALS - No credentials are available."},
    {SEC_E_NOT_OWNER, "SEC_E_NOT_OWNER - The caller of the function does not own the credentials."},
    {SEC_E_OUT_OF_SEQUENCE, "SEC_E_OUT_OF_SEQUENCE - The message was not received in the correct sequence."},
    {SEC_I_RENEGOTIATE, "SEC_I_RENEGOTIATE - The remote party requires a new handshake sequence or the application has just initiated a shutdown."},
    {SEC_E_SECPKG_NOT_FOUND, "SEC_E_SECPKG_NOT_FOUND - The security package was not recognized."},
    {SEC_E_TARGET_UNKNOWN, "SEC_E_TARGET_UNKNOWN - The target was not recognized."},
    {SEC_E_UNKNOWN_CREDENTIALS, "SEC_E_UNKNOWN_CREDENTIALS - The credentials provided were not recognized."},
    {SEC_E_UNSUPPORTED_FUNCTION, "SEC_E_UNSUPPORTED_FUNCTION - The requested function is not supported."},
    {SEC_E_WRONG_PRINCIPAL, "SEC_E_WRONG_PRINCIPAL - Certificate check failed."},
    {SEC_E_OK, "SEC_E_OK - The operation completed successfully."},
    {TRUST_E_ACTION_UNKNOWN, "TRUST_E_ACTION_UNKNOWN - The trust verification action specified is not supported by the specified trust provider."},
    {TRUST_E_BAD_DIGEST, "TRUST_E_BAD_DIGEST - The digital signature of the object did not verify."},
    {TRUST_E_BASIC_CONSTRAINTS, "TRUST_E_BASIC_CONSTRAINTS - A certificate's basic constraint extension has not been observed."},
    {TRUST_E_CERT_SIGNATURE, "TRUST_E_CERT_SIGNATURE - The signature of the certificate cannot be verified."},
    {TRUST_E_COUNTER_SIGNER, "TRUST_E_COUNTER_SIGNER - One of the counter signatures was invalid."},
    {TRUST_E_EXPLICIT_DISTRUST, "TRUST_E_EXPLICIT_DISTRUST - The certificate was explicitly marked as untrusted by the user."},
    {TRUST_E_FAIL, "TRUST_E_FAIL - Generic trust failure."},
    {TRUST_E_FINANCIAL_CRITERIA, "TRUST_E_FINANCIAL_CRITERIA - The certificate does not meet or contain the Authenticode(tm) financial extensions."},
    {TRUST_E_NOSIGNATURE, "TRUST_E_NOSIGNATURE - No signature was present in the subject."},
    {TRUST_E_NO_SIGNER_CERT, "TRUST_E_NO_SIGNER_CERT - The certificate for the signer of the message is invalid or not found."},
    {TRUST_E_PROVIDER_UNKNOWN, "TRUST_E_PROVIDER_UNKNOWN - Unknown trust provider."},
    {TRUST_E_SUBJECT_FORM_UNKNOWN, "TRUST_E_SUBJECT_FORM_UNKNOWN - The form specified for the subject is not one supported or known by the specified trust provider."},
    {TRUST_E_SUBJECT_NOT_TRUSTED, "TRUST_E_SUBJECT_NOT_TRUSTED - The subject is not trusted for the specified action."},
    {TRUST_E_SYSTEM_ERROR, "TRUST_E_SYSTEM_ERROR - A system-level error occurred while verifying trust."},
    {TRUST_E_TIME_STAMP, "TRUST_E_TIME_STAMP - The timestamp signature and/or certificate could not be verified or is malformed."}
  };

  for (int i = 0; i < (sizeof(security_status_as_string) / sizeof(*security_status_as_string)); i++) {
    if (security_status == security_status_as_string[i].first) {
      str_message = security_status_as_string[i].second;
      break;
    }
  }
  return str_message;
};

} // namespace tacopie

#endif /* _WIN32 */
