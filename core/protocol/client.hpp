#pragma once
// every action returns events, outgoing and so on, and saves the vault after any change

#include "protocol/contacts.hpp"
#include "protocol/dm.hpp"
#include "protocol/identity.hpp"
#include "protocol/vault.hpp"

#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace pqs::protocol {

inline constexpr std::size_t MAX_TEXT = 4000;
// per contact
inline constexpr std::size_t MAX_SEEN_REQUESTS = 1000;

class Client {
 public:
  static bool exists(const std::filesystem::path& dir, const std::string& user);
  static Client create(const std::filesystem::path& dir, const std::string& user, const std::string& passphrase,
                       const std::string& kdf_profile = "moderate");
  static Client open(const std::filesystem::path& dir, const std::string& user, const std::string& passphrase);

  json bundle() const { return make_bundle(id_); }
  json sign_login(ByteView challenge) const;

  json add_bundle(const json& bundle);
  json verify_contact(const std::string& user);
  json accept_key_change(const std::string& user);
  json safety_number(const std::string& user) const;
  json contacts() const;

  json dm_request(const std::string& to, const std::optional<std::string>& text = std::nullopt);
  json dm_accept(const std::string& peer);
  json dm_decline(const std::string& peer);
  json dm_send(const std::string& to, const std::string& text);

  // any envelope type from the server
  json receive(const json& envelope);

  json history(const std::string& conv, std::size_t limit = 200) const;
  json summary() const;

 private:
  Client(Vault vault, Identity id) : vault_(std::move(vault)), id_(std::move(id)) {}
  json state_json() const;
  void load_state(const json& state);
  void restore(const json& snapshot);
  json receive_inner(const json& envelope);
  void save() const { vault_.save(state_json()); }

  void receive_dm_request(const json& env, json& events, json& outgoing);
  void receive_dm_message(const json& env, json& events, json& outgoing);

  void add_history(const std::string& conv, json entry);
  void add_system(const std::string& conv, const std::string& text);
  Session& session_for(const std::string& peer);
  bool seen_request(const std::string& peer, const std::string& sid) const;
  void remember_request(const std::string& peer, const std::string& sid);

  Vault vault_;
  Identity id_;
  ContactBook contacts_;
  // by peer
  std::map<std::string, Session> sessions_;
  // by conv id
  std::map<std::string, std::vector<json>> history_;
  // peer -> mids we still owe a receipt for
  std::map<std::string, std::vector<std::string>> pending_receipts_;
  // user -> envelopes held while a key change is pending
  std::map<std::string, std::vector<json>> deferred_;
  // peer -> sids of requests already handled, replay guard
  std::map<std::string, std::vector<std::string>> seen_requests_;
};

}
