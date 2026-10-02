#pragma once
// tofu, a different identity key later blocks sending until the user accepts it

#include "protocol/identity.hpp"

#include <map>
#include <optional>
#include <string>

namespace pqs::protocol {

enum class Trust {
  // pinned on first use, not compared yet, ui shows a tilde
  Tofu,
  // safety numbers compared, ui shows a check
  Verified,
  // a different identity key showed up, needs a decision, ui shows a cross
  Changed,
};
// tofu, verified or changed
std::string trust_name(Trust t);

struct Contact {
  PublicIdentity pinned;
  std::int64_t first_seen = 0;
  bool verified = false;
  // new identity, not accepted yet
  std::optional<PublicIdentity> pending;
};

class ContactBook {
 public:
  enum class AddResult { New, Same, KemKeyUpdated, Changed };

  AddResult add(const PublicIdentity& id);
  const Contact* find(const std::string& user) const;
  // throws protocol error if unknown
  const Contact& get(const std::string& user) const;
  Trust trust(const std::string& user) const;

  // throws unless pinned and not changed, so safe to encrypt to
  const Contact& require_usable(const std::string& user) const;

  void mark_verified(const std::string& user);
  // pins the pending identity, back to unverified
  void accept_change(const std::string& user);

  const std::map<std::string, Contact>& all() const { return contacts_; }

  json to_json() const;
  static ContactBook from_json(const json& j);

 private:
  std::map<std::string, Contact> contacts_;
};

}
