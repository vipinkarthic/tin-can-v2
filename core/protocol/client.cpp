#include "protocol/client.hpp"

#include "crypto/kem.hpp"
#include "crypto/random.hpp"
#include "crypto/sig.hpp"

#include <algorithm>

namespace pqs::protocol {
namespace {

std::string dm_conv(const std::string& user) { return "dm:" + user; }
std::string new_mid() { return to_hex(random_bytes(8)); }

json result() { return {{"events", json::array()}, {"outgoing", json::array()}}; }

void check_text(const std::string& text) {
  if (text.empty()) throw ProtocolError("message is empty");
  if (text.size() > MAX_TEXT) throw ProtocolError("message is too long");
}

std::string add_result_name(ContactBook::AddResult r) {
  switch (r) {
    case ContactBook::AddResult::New: return "new";
    case ContactBook::AddResult::Same: return "same";
    case ContactBook::AddResult::KemKeyUpdated: return "kem_key_updated";
    case ContactBook::AddResult::Changed: return "changed";
  }
  return "same";
}

}

// lifecycle and persistence

bool Client::exists(const std::filesystem::path& dir, const std::string& user) { return Vault::exists(dir, user); }

Client Client::create(const std::filesystem::path& dir, const std::string& user, const std::string& passphrase,
                      const std::string& kdf_profile) {
  Identity id = create_identity(user);
  json state = {{"identity", identity_to_json(id)}};
  Vault v = Vault::create(dir, user, passphrase, kdf_profile, state);
  Client c(std::move(v), std::move(id));
  c.save();
  return c;
}

Client Client::open(const std::filesystem::path& dir, const std::string& user, const std::string& passphrase) {
  auto [vault, state] = Vault::open(dir, user, passphrase);
  Identity id = identity_from_json(field(state, "identity"));
  if (id.kem_pk.size() != KEM_PUBLIC_KEY_SIZE || id.kem_sk.size() != KEM_SECRET_KEY_SIZE) {
    throw VaultError("the vault holds keys of the wrong size (damaged or from another version)");
  }
  Client c(std::move(vault), std::move(id));
  c.load_state(state);
  return c;
}

json Client::state_json() const {
  json sessions = json::object(), history = json::object(), receipts = json::object(), deferred = json::object(),
       seen = json::object();
  for (const auto& [peer, s] : sessions_) sessions[peer] = session_to_json(s);
  for (const auto& [conv, entries] : history_) history[conv] = entries;
  for (const auto& [peer, mids] : pending_receipts_) receipts[peer] = mids;
  for (const auto& [user, envs] : deferred_) deferred[user] = envs;
  for (const auto& [peer, sids] : seen_requests_) seen[peer] = sids;
  return {{"identity", identity_to_json(id_)}, {"contacts", contacts_.to_json()}, {"sessions", sessions},
          {"history", history},                {"pending_receipts", receipts},    {"deferred", deferred},
          {"seen_requests", seen}};
}

void Client::load_state(const json& state) {
  // copy each section into a local first, items on a temporary dangles
  auto section = [&](const char* key) { return state.contains(key) ? state.at(key) : json::object(); };
  if (state.contains("contacts")) contacts_ = ContactBook::from_json(state.at("contacts"));
  const json sessions = section("sessions"), history = section("history"), receipts = section("pending_receipts"),
             deferred = section("deferred"), seen = section("seen_requests");
  for (const auto& [peer, s] : sessions.items()) sessions_[peer] = session_from_json(s);
  for (const auto& [conv, e] : history.items()) history_[conv] = e.get<std::vector<json>>();
  for (const auto& [peer, m] : receipts.items()) pending_receipts_[peer] = m.get<std::vector<std::string>>();
  for (const auto& [peer, m] : seen.items()) seen_requests_[peer] = m.get<std::vector<std::string>>();
  for (const auto& [user, e] : deferred.items()) deferred_[user] = e.get<std::vector<json>>();
}

void Client::restore(const json& snapshot) {
  contacts_ = ContactBook{};
  sessions_.clear();
  history_.clear();
  pending_receipts_.clear();
  deferred_.clear();
  seen_requests_.clear();
  load_state(snapshot);
}

json Client::sign_login(ByteView challenge) const {
  if (challenge.size() < 16 || challenge.size() > 64) throw ProtocolError("login challenge has an unexpected size");
  return {{"sig", b64(mldsa_sign(id_.sig_sk, login_transcript(id_.user, challenge)))}};
}

// history helpers

void Client::add_history(const std::string& conv, json entry) { history_[conv].push_back(std::move(entry)); }

void Client::add_system(const std::string& conv, const std::string& text) {
  add_history(conv, {{"kind", "system"}, {"text", text}, {"ts", now_ms()}});
}

Session& Client::session_for(const std::string& peer) {
  auto it = sessions_.find(peer);
  if (it == sessions_.end()) throw ProtocolError("no conversation with " + peer + "; send a request first");
  return it->second;
}

// sid comes from the signed transcript, so a replayed request keeps its old sid and gets ignored
bool Client::seen_request(const std::string& peer, const std::string& sid) const {
  auto it = seen_requests_.find(peer);
  return it != seen_requests_.end() && std::find(it->second.begin(), it->second.end(), sid) != it->second.end();
}

void Client::remember_request(const std::string& peer, const std::string& sid) {
  auto& sids = seen_requests_[peer];
  sids.push_back(sid);
  if (sids.size() > MAX_SEEN_REQUESTS) sids.erase(sids.begin());
}

json Client::history(const std::string& conv, std::size_t limit) const {
  auto it = history_.find(conv);
  if (it == history_.end()) return json::array();
  const auto& all = it->second;
  const std::size_t start = all.size() > limit ? all.size() - limit : 0;
  return json(std::vector<json>(all.begin() + static_cast<std::ptrdiff_t>(start), all.end()));
}

// contacts

json Client::add_bundle(const json& bundle) {
  const PublicIdentity p = verify_bundle(bundle);
  if (p.user == id_.user) throw ProtocolError("that is your own bundle");
  const auto r = contacts_.add(p);
  json out = result();
  out["user"] = p.user;
  out["status"] = add_result_name(r);
  out["trust"] = trust_name(contacts_.trust(p.user));
  out["fingerprint"] = fingerprint(contacts_.get(p.user).pinned.sig_pk);
  if (r == ContactBook::AddResult::Changed) {
    out["events"].push_back({{"event", "key_changed"}, {"user", p.user}});
    add_system(dm_conv(p.user), p.user + "'s identity key changed - compare safety numbers before continuing");
  }
  if (r != ContactBook::AddResult::Same) save();
  return out;
}

json Client::verify_contact(const std::string& user) {
  contacts_.mark_verified(user);
  add_system(dm_conv(user), "you verified " + user + "'s safety number");
  save();
  json out = result();
  out["trust"] = trust_name(contacts_.trust(user));
  return out;
}

json Client::accept_key_change(const std::string& user) {
  contacts_.accept_change(user);
  // old session is bound to the old identity key, so drop it
  if (sessions_.erase(user)) add_system(dm_conv(user), "the old session with " + user + " was closed");
  add_system(dm_conv(user), "you accepted " + user + "'s new identity key");
  json out = result();
  out["trust"] = trust_name(contacts_.trust(user));
  save();
  // now process whatever got deferred during the key change
  auto it = deferred_.find(user);
  if (it != deferred_.end()) {
    const std::vector<json> held = std::move(it->second);
    deferred_.erase(it);
    save();
    for (const auto& env : held) {
      try {
        json r = receive(env);
        for (auto& e : r["events"]) out["events"].push_back(e);
        for (auto& o : r["outgoing"]) out["outgoing"].push_back(o);
      } catch (const ProtocolError& e) {
        out["events"].push_back({{"event", "rejected"}, {"reason", e.what()}});
      }
    }
  }
  return out;
}

json Client::safety_number(const std::string& user) const {
  const Contact& c = contacts_.get(user);
  const PublicIdentity& them = c.pending ? *c.pending : c.pinned;
  return {{"user", user},
          {"digits", protocol::safety_number(id_.user, id_.sig_pk, them.user, them.sig_pk)},
          {"fingerprint_me", fingerprint(id_.sig_pk)},
          {"fingerprint_them", fingerprint(them.sig_pk)},
          {"trust", trust_name(contacts_.trust(user))},
          {"pending_change", c.pending.has_value()}};
}

json Client::contacts() const {
  json out = json::array();
  for (const auto& [user, c] : contacts_.all()) {
    const auto s = sessions_.find(user);
    out.push_back({{"user", user},
                   {"trust", trust_name(contacts_.trust(user))},
                   {"fingerprint", fingerprint(c.pinned.sig_pk)},
                   {"session", s == sessions_.end() ? json(nullptr) : json(state_name(s->second.state))}});
  }
  return out;
}

// direct messages

json Client::dm_request(const std::string& to, const std::optional<std::string>& text) {
  if (to == id_.user) throw ProtocolError("you cannot message yourself");
  const Contact& c = contacts_.require_usable(to);
  if (auto it = sessions_.find(to); it != sessions_.end()) {
    if (it->second.state == SessionState::Active) throw ProtocolError("you already have a conversation with " + to);
    if (it->second.state == SessionState::PendingIn) throw ProtocolError(to + " already sent you a request; accept it instead");
  }
  if (text) check_text(*text);
  DmRequest req = dm_create_request(id_, c);
  json out = result();
  out["outgoing"].push_back(req.envelope);
  sessions_[to] = std::move(req.session);
  add_system(dm_conv(to), "message request sent to " + to);
  if (text) {
    const std::string mid = new_mid();
    const json payload = {{"k", "text"}, {"mid", mid}, {"text", *text}, {"ts", now_ms()}};
    out["outgoing"].push_back(dm_encrypt(id_, sessions_[to], payload));
    add_history(dm_conv(to), {{"kind", "msg"}, {"mid", mid}, {"from", id_.user}, {"text", *text},
                              {"ts", payload["ts"]}, {"dir", "out"}, {"status", "sent"}});
    out["mid"] = mid;
  }
  save();
  return out;
}

json Client::dm_accept(const std::string& peer) {
  Session& s = session_for(peer);
  contacts_.require_usable(peer);
  json out = result();
  out["outgoing"].push_back(dm_make_accept(id_, s));
  add_system(dm_conv(peer), "you accepted " + peer + "'s request");
  // send receipts for everything that came in while pending
  if (auto it = pending_receipts_.find(peer); it != pending_receipts_.end()) {
    out["outgoing"].push_back(dm_encrypt(id_, s, {{"k", "receipt"}, {"mids", it->second}}));
    pending_receipts_.erase(it);
  }
  save();
  return out;
}

json Client::dm_decline(const std::string& peer) {
  Session& s = session_for(peer);
  if (s.state != SessionState::PendingIn) throw ProtocolError("there is no pending request from " + peer);
  json out = result();
  out["outgoing"].push_back(dm_make_decline(id_, s));
  sessions_.erase(peer);
  pending_receipts_.erase(peer);
  add_system(dm_conv(peer), "you declined " + peer + "'s request");
  save();
  return out;
}

json Client::dm_send(const std::string& to, const std::string& text) {
  check_text(text);
  contacts_.require_usable(to);
  Session& s = session_for(to);
  const std::string mid = new_mid();
  const json payload = {{"k", "text"}, {"mid", mid}, {"text", text}, {"ts", now_ms()}};
  json out = result();
  out["outgoing"].push_back(dm_encrypt(id_, s, payload));
  add_history(dm_conv(to), {{"kind", "msg"}, {"mid", mid}, {"from", id_.user}, {"text", text},
                            {"ts", payload["ts"]}, {"dir", "out"}, {"status", "sent"}});
  out["mid"] = mid;
  save();
  return out;
}

// receiving

json Client::receive(const json& env) {
  // all or nothing, roll back in memory state if anything in the envelope is rejected
  const json snapshot = state_json();
  try {
    return receive_inner(env);
  } catch (...) {
    restore(snapshot);
    throw;
  }
}

json Client::receive_inner(const json& env) {
  const std::string type = str_field(env, "type");
  json out = result();
  const bool direct = type == "dm_request" || type == "dm_accept" || type == "dm_decline" || type == "dm_msg";
  if (direct && str_field(env, "to") != id_.user) throw ProtocolError("envelope is addressed to someone else");

  if (type == "dm_request") {
    receive_dm_request(env, out["events"], out["outgoing"]);
  } else if (type == "dm_accept") {
    const std::string peer = str_field(env, "from");
    Session& s = session_for(peer);
    dm_handle_accept(s, contacts_.require_usable(peer), env);
    add_system(dm_conv(peer), peer + " accepted your request");
    out["events"].push_back({{"event", "dm_accepted"}, {"peer", peer}, {"conv", dm_conv(peer)}});
  } else if (type == "dm_decline") {
    const std::string peer = str_field(env, "from");
    const Session& s = session_for(peer);
    dm_check_decline(s, contacts_.get(peer), env);
    sessions_.erase(peer);
    add_system(dm_conv(peer), peer + " declined your request");
    out["events"].push_back({{"event", "dm_declined"}, {"peer", peer}, {"conv", dm_conv(peer)}});
  } else if (type == "dm_msg") {
    receive_dm_message(env, out["events"], out["outgoing"]);
  } else {
    throw ProtocolError("unknown envelope type: " + type);
  }
  save();
  return out;
}

void Client::receive_dm_request(const json& env, json& events, json& outgoing) {
  const PublicIdentity sender = dm_request_sender(env);
  if (sender.user == id_.user) throw ProtocolError("request from yourself");
  const auto added = contacts_.add(sender);
  if (added == ContactBook::AddResult::Changed) {
    // hold it until the user decides on the new key
    deferred_[sender.user].push_back(env);
    add_system(dm_conv(sender.user), sender.user + "'s identity key changed - compare safety numbers before continuing");
    events.push_back({{"event", "key_changed"}, {"user", sender.user}, {"conv", dm_conv(sender.user)}});
    return;
  }
  const Contact& from = contacts_.get(sender.user);

  // duplicate delivery or replay, ignore
  if (seen_request(sender.user, str_field(env, "sid"))) return;

  if (auto it = sessions_.find(sender.user); it != sessions_.end()) {
    Session& existing = it->second;
    // duplicate of the current sessions request
    if (existing.sid == str_field(env, "sid")) return;
    if (existing.state == SessionState::PendingOut) {
      // crossed requests, smaller username wins and gets auto accepted
      if (sender.user > id_.user) return;
      Session s = dm_open_request(id_, from, env);
      remember_request(sender.user, s.sid);
      outgoing.push_back(dm_make_accept(id_, s));
      existing = std::move(s);
      add_system(dm_conv(sender.user), "you and " + sender.user + " requested each other - conversation started");
      events.push_back({{"event", "dm_accepted"}, {"peer", sender.user}, {"conv", dm_conv(sender.user)}});
      return;
    }
  }
  Session s = dm_open_request(id_, from, env);
  remember_request(sender.user, s.sid);
  sessions_[sender.user] = std::move(s);
  add_system(dm_conv(sender.user), sender.user + " wants to message you");
  events.push_back({{"event", "dm_request"}, {"peer", sender.user}, {"conv", dm_conv(sender.user)},
                    {"trust", trust_name(contacts_.trust(sender.user))}, {"key_status", add_result_name(added)}});
}

void Client::receive_dm_message(const json& env, json& events, json& outgoing) {
  const std::string peer = str_field(env, "from");
  if (const Contact* c = contacts_.find(peer); c && c->pending) {
    deferred_[peer].push_back(env);
    return;
  }
  Session& s = session_for(peer);
  const json payload = dm_decrypt(s, env);
  const std::string kind = payload.value("k", "");
  const std::string conv = dm_conv(peer);
  if (kind == "text") {
    const std::string mid = str_field(payload, "mid"), text = str_field(payload, "text");
    if (text.size() > MAX_TEXT) throw ProtocolError("message is too long");
    const auto ts = payload.value("ts", now_ms());
    add_history(conv, {{"kind", "msg"}, {"mid", mid}, {"from", peer}, {"text", text}, {"ts", ts}, {"dir", "in"}});
    events.push_back({{"event", "message"}, {"conv", conv}, {"mid", mid}, {"from", peer}, {"text", text}, {"ts", ts}});
    if (s.state == SessionState::Active) {
      outgoing.push_back(dm_encrypt(id_, s, {{"k", "receipt"}, {"mids", json::array({mid})}}));
    } else {
      // receipt goes out once we accept
      pending_receipts_[peer].push_back(mid);
    }
  } else if (kind == "receipt") {
    json mids = json::array();
    for (const auto& m : field(payload, "mids")) {
      const std::string mid = m.get<std::string>();
      for (auto& e : history_[conv]) {
        if (e.value("mid", "") == mid && e.value("dir", "") == "out" && e.value("status", "") != "delivered") {
          e["status"] = "delivered";
          mids.push_back(mid);
        }
      }
    }
    if (!mids.empty()) events.push_back({{"event", "delivered"}, {"conv", conv}, {"mids", mids}});
  } else {
    throw ProtocolError("unknown message kind");
  }
}

// overview for the ui

json Client::summary() const {
  json dms = json::array();
  for (const auto& [peer, s] : sessions_) {
    dms.push_back({{"peer", peer}, {"conv", dm_conv(peer)}, {"state", state_name(s.state)},
                   {"trust", trust_name(contacts_.trust(peer))}, {"send_n", s.send.n}, {"recv_n", s.recv.n}});
  }
  // ended sessions, declined or key change, stay listed as closed so history is kept
  for (const auto& [conv, entries] : history_) {
    if (conv.rfind("dm:", 0) != 0 || entries.empty()) continue;
    const std::string peer = conv.substr(3);
    if (sessions_.count(peer) || !contacts_.find(peer)) continue;
    dms.push_back({{"peer", peer}, {"conv", conv}, {"state", "closed"}, {"trust", trust_name(contacts_.trust(peer))},
                   {"send_n", 0}, {"recv_n", 0}});
  }
  return {{"user", id_.user}, {"fingerprint", fingerprint(id_.sig_pk)}, {"contacts", contacts()}, {"dms", dms}};
}

}
