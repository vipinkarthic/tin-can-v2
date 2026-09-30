#pragma once

#include "crypto/bytes.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <memory>
#include <stdexcept>
#include <string>

namespace pqs::openssl {

struct PkeyFree { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct PkeyCtxFree { void operator()(EVP_PKEY_CTX* c) const { EVP_PKEY_CTX_free(c); } };
struct SignatureFree { void operator()(EVP_SIGNATURE* s) const { EVP_SIGNATURE_free(s); } };
using Pkey = std::unique_ptr<EVP_PKEY, PkeyFree>;
using PkeyCtx = std::unique_ptr<EVP_PKEY_CTX, PkeyCtxFree>;
using Signature = std::unique_ptr<EVP_SIGNATURE, SignatureFree>;

inline void check(bool ok, const char* what) {
  if (ok) return;
  char buf[256] = "unknown error";
  if (unsigned long e = ERR_get_error()) ERR_error_string_n(e, buf, sizeof(buf));
  ERR_clear_error();
  throw std::runtime_error(std::string("OpenSSL ") + what + " failed: " + buf);
}

inline Bytes raw_public_key(const EVP_PKEY* key) {
  std::size_t len = 0;
  check(EVP_PKEY_get_raw_public_key(key, nullptr, &len) == 1, "get public key size");
  Bytes out(len);
  check(EVP_PKEY_get_raw_public_key(key, out.data(), &len) == 1, "get public key");
  return out;
}

inline Bytes raw_private_key(const EVP_PKEY* key) {
  std::size_t len = 0;
  check(EVP_PKEY_get_raw_private_key(key, nullptr, &len) == 1, "get private key size");
  Bytes out(len);
  check(EVP_PKEY_get_raw_private_key(key, out.data(), &len) == 1, "get private key");
  return out;
}

}
