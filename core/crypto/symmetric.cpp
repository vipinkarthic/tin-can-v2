#include "crypto/symmetric.hpp"

#include <stdexcept>

namespace pqs {

Bytes aead_seal(ByteView key, ByteView plaintext, ByteView ad) {
  if (key.size() != AEAD_KEY_SIZE) throw std::invalid_argument("AEAD key must be 32 bytes");
  Bytes out(AEAD_NONCE_SIZE + plaintext.size() + AEAD_TAG_SIZE);
  randombytes_buf(out.data(), AEAD_NONCE_SIZE);
  unsigned long long ct_len = 0;
  crypto_aead_xchacha20poly1305_ietf_encrypt(out.data() + AEAD_NONCE_SIZE, &ct_len, plaintext.data(), plaintext.size(),
                                             ad.data(), ad.size(), nullptr, out.data(), key.data());
  out.resize(AEAD_NONCE_SIZE + ct_len);
  return out;
}

std::optional<Bytes> aead_open(ByteView key, ByteView sealed, ByteView ad) {
  if (key.size() != AEAD_KEY_SIZE || sealed.size() < AEAD_NONCE_SIZE + AEAD_TAG_SIZE) return std::nullopt;
  Bytes out(sealed.size() - AEAD_NONCE_SIZE - AEAD_TAG_SIZE);
  unsigned long long pt_len = 0;
  if (crypto_aead_xchacha20poly1305_ietf_decrypt(out.data(), &pt_len, nullptr, sealed.data() + AEAD_NONCE_SIZE,
                                                 sealed.size() - AEAD_NONCE_SIZE, ad.data(), ad.size(), sealed.data(),
                                                 key.data()) != 0) {
    return std::nullopt;
  }
  out.resize(pt_len);
  return out;
}

Bytes hmac_sha256(ByteView key, ByteView data) {
  crypto_auth_hmacsha256_state st;
  crypto_auth_hmacsha256_init(&st, key.data(), key.size());
  crypto_auth_hmacsha256_update(&st, data.data(), data.size());
  Bytes out(crypto_auth_hmacsha256_BYTES);
  crypto_auth_hmacsha256_final(&st, out.data());
  sodium_memzero(&st, sizeof(st));
  return out;
}

PwhashParams pwhash_profile(std::string_view name) {
  if (name == "moderate") return {crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE};
  if (name == "interactive") return {crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE};
  if (name == "min") return {crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN};
  throw std::invalid_argument("unknown pwhash profile");
}

Bytes argon2id(std::string_view passphrase, ByteView salt, PwhashParams params, std::size_t length) {
  if (salt.size() != PWHASH_SALT_SIZE) throw std::invalid_argument("Argon2id salt must be 16 bytes");
  Bytes out(length);
  if (crypto_pwhash(out.data(), out.size(), passphrase.data(), passphrase.size(), salt.data(), params.ops,
                    params.mem_bytes, crypto_pwhash_ALG_ARGON2ID13) != 0) {
    throw std::runtime_error("Argon2id failed (out of memory?)");
  }
  return out;
}

}
