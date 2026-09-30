#pragma once
// libsodium xchacha20 poly1305 aead, hmac sha256, argon2id

#include "crypto/bytes.hpp"

#include <cstdint>
#include <optional>
#include <string_view>

namespace pqs {

inline constexpr std::size_t AEAD_KEY_SIZE = 32;
inline constexpr std::size_t AEAD_NONCE_SIZE = 24;
inline constexpr std::size_t AEAD_TAG_SIZE = 16;

// returns nonce, ct, tag glued together, a random 192 bit nonce per call is safe with xchacha
Bytes aead_seal(ByteView key, ByteView plaintext, ByteView ad);
// nullopt on wrong key or any tampering of ct, tag, nonce or ad
std::optional<Bytes> aead_open(ByteView key, ByteView sealed, ByteView ad);

Bytes hmac_sha256(ByteView key, ByteView data);

// moderate is the vault default, min is only there to keep tests fast
struct PwhashParams {
  std::uint64_t ops;
  std::size_t mem_bytes;
};
// throws invalid argument
PwhashParams pwhash_profile(std::string_view name);
inline constexpr std::size_t PWHASH_SALT_SIZE = 16;
Bytes argon2id(std::string_view passphrase, ByteView salt, PwhashParams params, std::size_t length = 32);

}
