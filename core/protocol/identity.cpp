#include "protocol/identity.hpp"

#include "crypto/hash.hpp"
#include "crypto/kem.hpp"
#include "crypto/sig.hpp"

#include <cstdio>

namespace pqs::protocol {
namespace {

Bytes bundle_transcript(const std::string& user, ByteView sig_pk, ByteView kem_pk, std::int64_t created) {
  return Transcript("pqs/bundle/v1")
      .add(user)
      .add(SIG_ALG)
      .add(KEM_ALG)
      .add(sig_pk)
      .add(kem_pk)
      .add(static_cast<std::uint64_t>(created))
      .bytes();
}

// 30 decimal digits for one side of a safety number
std::string safety_half(const std::string& user, ByteView sig_pk) {
  const std::uint8_t version[2] = {0, 0};
  Bytes h = sha3_512({ByteView(version, 2), sig_pk, view(user)});
  for (int i = 0; i < 5200; ++i) h = sha3_512({h, sig_pk});
  std::string digits;
  for (int chunk = 0; chunk < 6; ++chunk) {
    std::uint64_t v = 0;
    for (int b = 0; b < 5; ++b) v = (v << 8) | h[static_cast<std::size_t>(chunk * 5 + b)];
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%05llu", static_cast<unsigned long long>(v % 100000));
    digits += buf;
  }
  return digits;
}

}

bool valid_username(std::string_view user) {
  if (user.empty() || user.size() > 32) return false;
  for (char c : user)
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return false;
  return true;
}

Identity create_identity(const std::string& user) {
  if (!valid_username(user)) throw ProtocolError("username must be 1-32 characters of a-z, 0-9 or _");
  SigKeyPair s = mldsa_keygen();
  KemKeyPair k = kem_keygen();
  return {user, std::move(s.pk), std::move(s.sk), std::move(k.pk), std::move(k.sk), now_ms()};
}

json make_bundle(const Identity& id) {
  const Bytes sig = mldsa_sign(id.sig_sk, bundle_transcript(id.user, id.sig_pk, id.kem_pk, id.created));
  return {{"v", WIRE_VERSION},  {"type", "bundle"},       {"user", id.user},
          {"sig_alg", SIG_ALG}, {"kem_alg", KEM_ALG},     {"sig_pk", b64(id.sig_pk)},
          {"kem_pk", b64(id.kem_pk)}, {"created", id.created}, {"sig", b64(sig)}};
}

PublicIdentity verify_bundle(const json& bundle) {
  expect_type(bundle, "bundle");
  PublicIdentity p;
  p.user = str_field(bundle, "user");
  if (!valid_username(p.user)) throw ProtocolError("bundle has an invalid username");
  if (str_field(bundle, "sig_alg") != SIG_ALG || str_field(bundle, "kem_alg") != KEM_ALG) {
    throw ProtocolError("bundle uses unsupported algorithms");
  }
  p.sig_pk = b64_field(bundle, "sig_pk");
  p.kem_pk = b64_field(bundle, "kem_pk");
  p.created = static_cast<std::int64_t>(uint_field(bundle, "created"));
  if (p.sig_pk.size() != MLDSA65_PUBLIC_KEY_SIZE || p.kem_pk.size() != KEM_PUBLIC_KEY_SIZE) {
    throw ProtocolError("bundle keys have the wrong size");
  }
  if (!mldsa_verify(p.sig_pk, bundle_transcript(p.user, p.sig_pk, p.kem_pk, p.created), b64_field(bundle, "sig"))) {
    throw ProtocolError("bundle signature is invalid");
  }
  return p;
}

std::string fingerprint(ByteView sig_pk) {
  const std::string hex = to_hex(sha3_256({view("pqs/fingerprint/v1"), sig_pk}));
  std::string out;
  for (int i = 0; i < 16; i += 4) {
    if (!out.empty()) out += ' ';
    out += hex.substr(static_cast<std::size_t>(i), 4);
  }
  return out;
}

std::vector<std::string> safety_number(const std::string& user_a, ByteView sig_pk_a, const std::string& user_b,
                                       ByteView sig_pk_b) {
  std::string a = safety_half(user_a, sig_pk_a), b = safety_half(user_b, sig_pk_b);
  const std::string all = user_a < user_b ? a + b : b + a;
  std::vector<std::string> groups;
  for (std::size_t i = 0; i < all.size(); i += 5) groups.push_back(all.substr(i, 5));
  return groups;
}

Bytes login_transcript(const std::string& user, ByteView challenge) {
  return Transcript("pqs/login/v1").add(user).add(challenge).bytes();
}

json identity_to_json(const Identity& id) {
  return {{"user", id.user},           {"sig_pk", b64(id.sig_pk)}, {"sig_sk", b64(id.sig_sk)},
          {"kem_pk", b64(id.kem_pk)},  {"kem_sk", b64(id.kem_sk)}, {"created", id.created}};
}

Identity identity_from_json(const json& j) {
  return {str_field(j, "user"),   b64_field(j, "sig_pk"), b64_field(j, "sig_sk"), b64_field(j, "kem_pk"),
          b64_field(j, "kem_sk"), j.at("created").get<std::int64_t>()};
}

}
