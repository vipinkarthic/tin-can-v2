#pragma once
// ad binds user and kdf params, so a vault copied to another username wont open

#include "protocol/common.hpp"

#include <filesystem>
#include <string>
#include <utility>

namespace pqs::protocol {

struct VaultError : ProtocolError {
  using ProtocolError::ProtocolError;
};

inline constexpr std::size_t MIN_PASSPHRASE = 8;
inline constexpr std::size_t MAX_PASSPHRASE = 1024;

class Vault {
 public:
  static std::filesystem::path path_for(const std::filesystem::path& dir, const std::string& user);
  static bool exists(const std::filesystem::path& dir, const std::string& user);

  // fails if a vault already exists
  static Vault create(const std::filesystem::path& dir, const std::string& user, const std::string& passphrase,
                      const std::string& kdf_profile, const json& state);
  static std::pair<Vault, json> open(const std::filesystem::path& dir, const std::string& user, const std::string& passphrase);

  void save(const json& state) const;

  Vault(Vault&& other) noexcept;
  Vault& operator=(Vault&& other) noexcept;
  Vault(const Vault&) = delete;
  Vault& operator=(const Vault&) = delete;
  ~Vault();

 private:
  Vault() = default;
  // flock on the users lock file while open, so two processes cant clobber the same ratchet state
  int lock_fd_ = -1;
  void lock(const std::filesystem::path& dir, const std::string& user);
  std::filesystem::path path_;
  std::string user_;
  Bytes key_;
  json kdf_;
  Bytes ad_;
};

}
