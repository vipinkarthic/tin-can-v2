#pragma once
// bundle sig covers the kem key too, so the server cant swap it

#include "protocol/common.hpp"

#include <string>
#include <vector>

namespace pqs::protocol {

inline constexpr std::string_view SIG_ALG = "ml-dsa-65";
inline constexpr std::string_view KEM_ALG = "ml-kem-768";

struct Identity {
  std::string user;
  Bytes sig_pk, sig_sk;
  Bytes kem_pk, kem_sk;
  std::int64_t created = 0;
};

// whats left of a bundle after verify bundle passes
struct PublicIdentity {
  std::string user;
  Bytes sig_pk;
  Bytes kem_pk;
  std::int64_t created = 0;
};

// 1 to 32 chars, a to z, 0 to 9 and underscore
bool valid_username(std::string_view user);

Identity create_identity(const std::string& user);
json make_bundle(const Identity& id);
// throws protocol error
PublicIdentity verify_bundle(const json& bundle);

// short fingerprint, looks like 9c1e 4a07 d3b2 77e1
std::string fingerprint(ByteView sig_pk);

// 5200 rounds of sha3 512 per side like signal, halves ordered by username so both sides match
std::vector<std::string> safety_number(const std::string& user_a, ByteView sig_pk_a, const std::string& user_b,
                                       ByteView sig_pk_b);

Bytes login_transcript(const std::string& user, ByteView challenge);

json identity_to_json(const Identity& id);
Identity identity_from_json(const json& j);

}
