#pragma once
// dm, signed kem request -> signed accept with key confirm, then hash ratchet msgs

#include "protocol/contacts.hpp"
#include "protocol/identity.hpp"
#include "protocol/ratchet.hpp"

namespace pqs::protocol {

enum class SessionState { PendingOut, PendingIn, Active };
// pending out, pending in or active
std::string state_name(SessionState s);

struct Session {
  std::string peer;
  std::string sid;
  SessionState state = SessionState::PendingOut;
  bool initiator = false;
  // transcript hash, binds the whole handshake
  Bytes th;
  // cleared once the accept is checked
  Bytes confirm_key;
  SendChain send;
  RecvChain recv;
  std::int64_t created = 0;
};

struct DmRequest {
  Session session;
  json envelope;
};

DmRequest dm_create_request(const Identity& me, const Contact& peer);

// verified but not trusted yet, run it through the contact book first
PublicIdentity dm_request_sender(const json& request);

// responder side, checks against the pinned contact, not the embedded bundle
Session dm_open_request(const Identity& me, const Contact& from, const json& request);

// pending in -> active
json dm_make_accept(const Identity& me, Session& s);
// pending out -> active
void dm_handle_accept(Session& s, const Contact& peer, const json& accept);
json dm_make_decline(const Identity& me, const Session& s);
// throws if forged
void dm_check_decline(const Session& s, const Contact& peer, const json& decline);

// only the initiator can send before accept, the other side can read but not reply yet
json dm_encrypt(const Identity& me, Session& s, const json& payload);
// ratchet state only moves on success
json dm_decrypt(Session& s, const json& message);

json session_to_json(const Session& s);
Session session_from_json(const json& j);

}
