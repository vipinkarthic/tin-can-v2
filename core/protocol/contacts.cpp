#include "protocol/contacts.hpp"

namespace pqs::protocol {
namespace {

json public_to_json(const PublicIdentity& p) {
  return {{"user", p.user}, {"sig_pk", b64(p.sig_pk)}, {"kem_pk", b64(p.kem_pk)}, {"created", p.created}};
}

PublicIdentity public_from_json(const json& j) {
  return {str_field(j, "user"), b64_field(j, "sig_pk"), b64_field(j, "kem_pk"), j.at("created").get<std::int64_t>()};
}

}

std::string trust_name(Trust t) {
  switch (t) {
    case Trust::Tofu: return "tofu";
    case Trust::Verified: return "verified";
    case Trust::Changed: return "changed";
  }
  return "tofu";
}

ContactBook::AddResult ContactBook::add(const PublicIdentity& id) {
  auto it = contacts_.find(id.user);
  if (it == contacts_.end()) {
    contacts_[id.user] = Contact{id, now_ms(), false, std::nullopt};
    return AddResult::New;
  }
  Contact& c = it->second;
  if (ct_equal(c.pinned.sig_pk, id.sig_pk)) {
    if (ct_equal(c.pinned.kem_pk, id.kem_pk)) return AddResult::Same;
    // ignore older bundles so a replay cant roll the kem key back
    if (id.created < c.pinned.created) return AddResult::Same;
    // same identity key, so a newer signed kem key is just a rotation
    c.pinned.kem_pk = id.kem_pk;
    c.pinned.created = id.created;
    return AddResult::KemKeyUpdated;
  }
  // different identity key, never replace the pin silently
  c.pending = id;
  return AddResult::Changed;
}

const Contact* ContactBook::find(const std::string& user) const {
  auto it = contacts_.find(user);
  return it == contacts_.end() ? nullptr : &it->second;
}

const Contact& ContactBook::get(const std::string& user) const {
  const Contact* c = find(user);
  if (!c) throw ProtocolError("unknown contact: " + user);
  return *c;
}

Trust ContactBook::trust(const std::string& user) const {
  const Contact& c = get(user);
  if (c.pending) return Trust::Changed;
  return c.verified ? Trust::Verified : Trust::Tofu;
}

const Contact& ContactBook::require_usable(const std::string& user) const {
  const Contact& c = get(user);
  if (c.pending) throw ProtocolError(user + "'s identity key changed; compare safety numbers and accept it first");
  return c;
}

void ContactBook::mark_verified(const std::string& user) {
  // throws if unknown
  get(user);
  Contact& c = contacts_.at(user);
  if (c.pending) throw ProtocolError(user + "'s identity key changed; accept or reject the new key first");
  c.verified = true;
}

void ContactBook::accept_change(const std::string& user) {
  get(user);
  Contact& c = contacts_.at(user);
  if (!c.pending) throw ProtocolError("no pending key change for " + user);
  c.pinned = *c.pending;
  c.pending.reset();
  c.verified = false;
}

json ContactBook::to_json() const {
  json out = json::object();
  for (const auto& [user, c] : contacts_) {
    out[user] = {{"pinned", public_to_json(c.pinned)},
                 {"first_seen", c.first_seen},
                 {"verified", c.verified},
                 {"pending", c.pending ? public_to_json(*c.pending) : json(nullptr)}};
  }
  return out;
}

ContactBook ContactBook::from_json(const json& j) {
  ContactBook book;
  for (const auto& [user, c] : j.items()) {
    Contact contact{public_from_json(c.at("pinned")), c.at("first_seen").get<std::int64_t>(), c.at("verified").get<bool>(),
                    std::nullopt};
    if (!c.at("pending").is_null()) contact.pending = public_from_json(c.at("pending"));
    book.contacts_[user] = std::move(contact);
  }
  return book;
}

}
