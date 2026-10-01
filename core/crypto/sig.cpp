#include "crypto/sig.hpp"

#include "crypto/openssl_util.hpp"

namespace pqs {
namespace {

constexpr const char* ALG = "ML-DSA-65";

openssl::Signature fetch_alg() {
  openssl::Signature alg(EVP_SIGNATURE_fetch(nullptr, ALG, nullptr));
  openssl::check(alg != nullptr, "ML-DSA fetch");
  return alg;
}

}

SigKeyPair mldsa_keygen() {
  openssl::Pkey key(EVP_PKEY_Q_keygen(nullptr, nullptr, ALG));
  openssl::check(key != nullptr, "ML-DSA keygen");
  return {openssl::raw_public_key(key.get()), openssl::raw_private_key(key.get())};
}

Bytes mldsa_sign(ByteView sk, ByteView message) {
  openssl::Pkey key(EVP_PKEY_new_raw_private_key_ex(nullptr, ALG, nullptr, sk.data(), sk.size()));
  openssl::check(key != nullptr, "ML-DSA import private key");
  const auto alg = fetch_alg();
  openssl::PkeyCtx ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr));
  openssl::check(ctx && EVP_PKEY_sign_message_init(ctx.get(), alg.get(), nullptr) == 1, "ML-DSA sign init");
  std::size_t len = 0;
  openssl::check(EVP_PKEY_sign(ctx.get(), nullptr, &len, message.data(), message.size()) == 1, "ML-DSA sign size");
  Bytes sig(len);
  openssl::check(EVP_PKEY_sign(ctx.get(), sig.data(), &len, message.data(), message.size()) == 1, "ML-DSA sign");
  sig.resize(len);
  return sig;
}

bool mldsa_verify(ByteView pk, ByteView message, ByteView signature) {
  if (pk.size() != MLDSA65_PUBLIC_KEY_SIZE || signature.size() != MLDSA65_SIGNATURE_SIZE) return false;
  openssl::Pkey key(EVP_PKEY_new_raw_public_key_ex(nullptr, ALG, nullptr, pk.data(), pk.size()));
  if (!key) {
    ERR_clear_error();
    return false;
  }
  const auto alg = fetch_alg();
  openssl::PkeyCtx ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr));
  const bool ok = ctx && EVP_PKEY_verify_message_init(ctx.get(), alg.get(), nullptr) == 1 &&
                  EVP_PKEY_verify(ctx.get(), signature.data(), signature.size(), message.data(), message.size()) == 1;
  ERR_clear_error();
  return ok;
}

}
