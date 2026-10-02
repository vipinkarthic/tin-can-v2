#include "protocol/dm.hpp"

#include "crypto/hash.hpp"
#include "crypto/kem.hpp"
#include "crypto/sig.hpp"
#include "crypto/symmetric.hpp"

namespace pqs::protocol {
namespace {

Bytes request_transcript(const std::string& from, ByteView from_sig_pk, ByteView from_kem_pk, const std::string& to,
                         ByteView to_sig_pk, ByteView to_kem_pk, ByteView kem_ct) {
  return Transcript("pqs/dm-request/v1")
      .add(from)
      .add(to)
      .add(from_sig_pk)
      .add(from_kem_pk)
      .add(to_sig_pk)
      .add(to_kem_pk)
      .add(kem_ct)
      .bytes();
}

std::string sid_from(ByteView th) { return to_hex(th.subspan(0, 16)); }

// root is hmac of ss keyed with th, ties the secret to this handshake, every key below gets its own label
void derive_keys(Session& s, ByteView shared) {
  const Bytes root = hmac_sha256(s.th, shared);
  Bytes a2b = hmac_sha256(root, view("pqs/dm/chain/initiator-to-responder/v1"));
  Bytes b2a = hmac_sha256(root, view("pqs/dm/chain/responder-to-initiator/v1"));
  s.confirm_key = hmac_sha256(root, view("pqs/dm/confirm/v1"));
  s.send = SendChain{s.initiator ? a2b : b2a, 0};
  s.recv = RecvChain{s.initiator ? b2a : a2b, 0, {}};
}

Bytes accept_transcript(ByteView th) { return Transcript("pqs/dm-accept/v1").add(th).bytes(); }

Bytes message_ad(const std::string& sid, const std::string& from, const std::string& to, std::uint64_t n) {
  return Transcript("pqs/dm-msg/v1").add(sid).add(from).add(to).add(n).bytes();
}

void expect_route(const json& env, const std::string& from, const std::string& to, const std::string& sid) {
  if (str_field(env, "from") != from || str_field(env, "to") != to) throw ProtocolError("envelope sender/recipient mismatch");
  if (str_field(env, "sid") != sid) throw ProtocolError("envelope is for a different session");
}

}

std::string state_name(SessionState s) {
  switch (s) {
    case SessionState::PendingOut: return "pending_out";
    case SessionState::PendingIn: return "pending_in";
    case SessionState::Active: return "active";
  }
  return "active";
}

DmRequest dm_create_request(const Identity& me, const Contact& peer) {
  const PublicIdentity& to = peer.pinned;
  const KemEncapsulation kem = kem_encaps(to.kem_pk);
  const Bytes t = request_transcript(me.user, me.sig_pk, me.kem_pk, to.user, to.sig_pk, to.kem_pk, kem.ciphertext);

  DmRequest out;
  Session& s = out.session;
  s.peer = to.user;
  s.initiator = true;
  s.state = SessionState::PendingOut;
  s.th = sha3_256({t});
  s.sid = sid_from(s.th);
  s.created = now_ms();
  derive_keys(s, kem.shared_key);

  out.envelope = {{"v", WIRE_VERSION},        {"type", "dm_request"},          {"from", me.user},
                  {"to", to.user},            {"sid", s.sid},                  {"kem_ct", b64(kem.ciphertext)},
                  {"from_bundle", make_bundle(me)}, {"sig", b64(mldsa_sign(me.sig_sk, t))}};
  return out;
}

PublicIdentity dm_request_sender(const json& request) {
  expect_type(request, "dm_request");
  PublicIdentity sender = verify_bundle(field(request, "from_bundle"));
  if (sender.user != str_field(request, "from")) throw ProtocolError("request bundle does not match the sender");
  return sender;
}

Session dm_open_request(const Identity& me, const Contact& from, const json& request) {
  expect_type(request, "dm_request");
  const PublicIdentity& peer = from.pinned;
  if (str_field(request, "from") != peer.user) throw ProtocolError("request sender mismatch");
  if (str_field(request, "to") != me.user) throw ProtocolError("request is addressed to someone else");

  const Bytes kem_ct = b64_field(request, "kem_ct");
  const Bytes t = request_transcript(peer.user, peer.sig_pk, peer.kem_pk, me.user, me.sig_pk, me.kem_pk, kem_ct);
  if (!mldsa_verify(peer.sig_pk, t, b64_field(request, "sig"))) {
    throw ProtocolError("request signature is invalid (or was made for an old key)");
  }

  Session s;
  s.peer = peer.user;
  s.initiator = false;
  s.state = SessionState::PendingIn;
  s.th = sha3_256({t});
  s.sid = sid_from(s.th);
  if (str_field(request, "sid") != s.sid) throw ProtocolError("request session id mismatch");
  s.created = now_ms();
  Bytes shared;
  try {
    shared = kem_decaps(me.kem_sk, kem_ct);
  } catch (const std::invalid_argument& e) {
    throw ProtocolError(std::string("request key exchange failed: ") + e.what());
  }
  derive_keys(s, shared);
  return s;
}

json dm_make_accept(const Identity& me, Session& s) {
  if (s.state != SessionState::PendingIn) throw ProtocolError("there is no pending request to accept");
  const Bytes confirm = hmac_sha256(s.confirm_key, accept_transcript(s.th));
  const Bytes sig = mldsa_sign(me.sig_sk, Transcript("pqs/dm-accept/v1").add(s.th).add(confirm).bytes());
  s.state = SessionState::Active;
  s.confirm_key.clear();
  return {{"v", WIRE_VERSION}, {"type", "dm_accept"}, {"from", me.user}, {"to", s.peer},
          {"sid", s.sid},      {"confirm", b64(confirm)}, {"sig", b64(sig)}};
}

void dm_handle_accept(Session& s, const Contact& peer, const json& accept) {
  expect_type(accept, "dm_accept");
  if (s.state != SessionState::PendingOut) throw ProtocolError("no outgoing request is waiting for an accept");
  expect_route(accept, s.peer, str_field(accept, "to"), s.sid);
  const Bytes confirm = b64_field(accept, "confirm");
  if (!ct_equal(confirm, hmac_sha256(s.confirm_key, accept_transcript(s.th)))) {
    throw ProtocolError("accept key confirmation failed");
  }
  if (!mldsa_verify(peer.pinned.sig_pk, Transcript("pqs/dm-accept/v1").add(s.th).add(confirm).bytes(),
                    b64_field(accept, "sig"))) {
    throw ProtocolError("accept signature is invalid");
  }
  s.state = SessionState::Active;
  s.confirm_key.clear();
}

json dm_make_decline(const Identity& me, const Session& s) {
  const Bytes sig = mldsa_sign(me.sig_sk, Transcript("pqs/dm-decline/v1").add(s.th).bytes());
  return {{"v", WIRE_VERSION}, {"type", "dm_decline"}, {"from", me.user}, {"to", s.peer}, {"sid", s.sid}, {"sig", b64(sig)}};
}

void dm_check_decline(const Session& s, const Contact& peer, const json& decline) {
  expect_type(decline, "dm_decline");
  expect_route(decline, s.peer, str_field(decline, "to"), s.sid);
  if (!mldsa_verify(peer.pinned.sig_pk, Transcript("pqs/dm-decline/v1").add(s.th).bytes(), b64_field(decline, "sig"))) {
    throw ProtocolError("decline signature is invalid");
  }
}

json dm_encrypt(const Identity& me, Session& s, const json& payload) {
  const bool can_send = s.state == SessionState::Active || (s.initiator && s.state == SessionState::PendingOut);
  if (!can_send) throw ProtocolError("accept the request before sending");
  auto [n, mk] = ratchet_send(s.send);
  std::string pt = payload.dump();
  const Bytes body = aead_seal(mk, view(pt), message_ad(s.sid, me.user, s.peer, n));
  sodium_memzero(pt.data(), pt.size());
  return {{"v", WIRE_VERSION}, {"type", "dm_msg"}, {"from", me.user}, {"to", s.peer},
          {"sid", s.sid},      {"n", n},           {"body", b64(body)}};
}

json dm_decrypt(Session& s, const json& message) {
  expect_type(message, "dm_msg");
  const std::string to = str_field(message, "to");
  expect_route(message, s.peer, to, s.sid);
  const bool can_receive = s.state == SessionState::Active || (!s.initiator && s.state == SessionState::PendingIn);
  if (!can_receive) throw ProtocolError("message arrived before the session was accepted");

  const std::uint64_t n64 = uint_field(message, "n");
  if (n64 > UINT32_MAX) throw ProtocolError("message counter out of range");
  const auto n = static_cast<std::uint32_t>(n64);
  RecvChain next;
  const Bytes mk = ratchet_recv(s.recv, n, next);
  auto pt = aead_open(mk, b64_field(message, "body"), message_ad(s.sid, s.peer, to, n));
  s.recv = std::move(next);
  if (!pt) throw ProtocolError("message failed to decrypt (tampered, or not for this session)");
  json payload = json::parse(pt->begin(), pt->end(), nullptr, false);
  if (payload.is_discarded() || !payload.is_object()) throw ProtocolError("message payload is not valid JSON");
  return payload;
}

json session_to_json(const Session& s) {
  return {{"peer", s.peer},
          {"sid", s.sid},
          {"state", state_name(s.state)},
          {"initiator", s.initiator},
          {"th", b64(s.th)},
          {"confirm_key", b64(s.confirm_key)},
          {"send", send_chain_to_json(s.send)},
          {"recv", recv_chain_to_json(s.recv)},
          {"created", s.created}};
}

Session session_from_json(const json& j) {
  Session s;
  s.peer = str_field(j, "peer");
  s.sid = str_field(j, "sid");
  const std::string st = str_field(j, "state");
  s.state = st == "pending_out" ? SessionState::PendingOut : st == "pending_in" ? SessionState::PendingIn : SessionState::Active;
  s.initiator = j.at("initiator").get<bool>();
  s.th = b64_field(j, "th");
  s.confirm_key = b64_field(j, "confirm_key");
  s.send = send_chain_from_json(field(j, "send"));
  s.recv = recv_chain_from_json(field(j, "recv"));
  s.created = j.at("created").get<std::int64_t>();
  return s;
}

}
