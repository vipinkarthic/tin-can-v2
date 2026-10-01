#include "crypto/openssl_mlkem.hpp"

#include "crypto/openssl_util.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <string>

namespace pqs::openssl {

kyber::KeyPair mlkem_keygen(std::string_view alg_name, ByteView seed) {
  const std::string alg(alg_name);
  PkeyCtx ctx(EVP_PKEY_CTX_new_from_name(nullptr, alg.c_str(), nullptr));
  check(ctx && EVP_PKEY_keygen_init(ctx.get()) == 1, "ML-KEM keygen init");
  if (!seed.empty()) {
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, const_cast<std::uint8_t*>(seed.data()), seed.size()),
        OSSL_PARAM_construct_end()};
    check(EVP_PKEY_CTX_set_params(ctx.get(), params) == 1, "ML-KEM keygen seed");
  }
  EVP_PKEY* raw = nullptr;
  check(EVP_PKEY_generate(ctx.get(), &raw) == 1, "ML-KEM keygen");
  Pkey key(raw);
  return {raw_public_key(key.get()), raw_private_key(key.get())};
}

kyber::Encapsulation mlkem_encaps(std::string_view alg_name, ByteView ek, ByteView m) {
  const std::string alg(alg_name);
  Pkey key(EVP_PKEY_new_raw_public_key_ex(nullptr, alg.c_str(), nullptr, ek.data(), ek.size()));
  check(key != nullptr, "ML-KEM import encapsulation key");
  PkeyCtx ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr));
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME, const_cast<std::uint8_t*>(m.data()), m.size()),
      OSSL_PARAM_construct_end()};
  check(ctx && EVP_PKEY_encapsulate_init(ctx.get(), m.empty() ? nullptr : params) == 1, "ML-KEM encaps init");
  std::size_t ct_len = 0, ss_len = 0;
  check(EVP_PKEY_encapsulate(ctx.get(), nullptr, &ct_len, nullptr, &ss_len) == 1, "ML-KEM encaps size");
  kyber::Encapsulation out;
  out.ciphertext.resize(ct_len);
  out.shared_key.resize(ss_len);
  check(EVP_PKEY_encapsulate(ctx.get(), out.ciphertext.data(), &ct_len, out.shared_key.data(), &ss_len) == 1,
        "ML-KEM encaps");
  return out;
}

Bytes mlkem_decaps(std::string_view alg_name, ByteView dk, ByteView c) {
  const std::string alg(alg_name);
  Pkey key(EVP_PKEY_new_raw_private_key_ex(nullptr, alg.c_str(), nullptr, dk.data(), dk.size()));
  check(key != nullptr, "ML-KEM import decapsulation key");
  PkeyCtx ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr));
  check(ctx && EVP_PKEY_decapsulate_init(ctx.get(), nullptr) == 1, "ML-KEM decaps init");
  std::size_t ss_len = 0;
  check(EVP_PKEY_decapsulate(ctx.get(), nullptr, &ss_len, c.data(), c.size()) == 1, "ML-KEM decaps size");
  Bytes ss(ss_len);
  check(EVP_PKEY_decapsulate(ctx.get(), ss.data(), &ss_len, c.data(), c.size()) == 1, "ML-KEM decaps");
  return ss;
}

}
