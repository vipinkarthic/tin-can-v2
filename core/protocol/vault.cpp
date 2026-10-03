#include "protocol/vault.hpp"

#include "crypto/random.hpp"
#include "crypto/symmetric.hpp"
#include "protocol/identity.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace pqs::protocol {
namespace {

Bytes vault_ad(const std::string& user, const json& kdf) {
  return Transcript("pqs/vault/v1")
      .add(user)
      .add(from_base64(kdf.at("salt").get<std::string>()))
      .add(kdf.at("ops").get<std::uint64_t>())
      .add(kdf.at("mem").get<std::uint64_t>())
      .bytes();
}

[[noreturn]] void fail_errno(const std::string& what) { throw VaultError(what + ": " + std::strerror(errno)); }

// temp file, fsync, rename, then fsync the dir so the rename survives a crash
void atomic_write(const fs::path& path, const std::string& data) {
  const fs::path tmp = path.string() + ".tmp";
  const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) fail_errno("cannot write vault");
  std::size_t off = 0;
  while (off < data.size()) {
    const ssize_t w = ::write(fd, data.data() + off, data.size() - off);
    if (w < 0) {
      if (errno == EINTR) continue;
      ::close(fd);
      fail_errno("cannot write vault");
    }
    off += static_cast<std::size_t>(w);
  }
  if (::fsync(fd) != 0) {
    ::close(fd);
    fail_errno("cannot sync vault");
  }
  ::close(fd);
  if (::rename(tmp.c_str(), path.c_str()) != 0) fail_errno("cannot replace vault");
  const int dfd = ::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dfd >= 0) {
    ::fsync(dfd);
    ::close(dfd);
  }
}

}

Vault::Vault(Vault&& o) noexcept
    : lock_fd_(o.lock_fd_), path_(std::move(o.path_)), user_(std::move(o.user_)), key_(std::move(o.key_)),
      kdf_(std::move(o.kdf_)), ad_(std::move(o.ad_)) {
  o.lock_fd_ = -1;
}

Vault& Vault::operator=(Vault&& o) noexcept {
  if (this != &o) {
    if (lock_fd_ >= 0) ::close(lock_fd_);
    lock_fd_ = o.lock_fd_;
    o.lock_fd_ = -1;
    path_ = std::move(o.path_);
    user_ = std::move(o.user_);
    key_ = std::move(o.key_);
    kdf_ = std::move(o.kdf_);
    ad_ = std::move(o.ad_);
  }
  return *this;
}

Vault::~Vault() {
  // closing the fd drops the flock
  if (lock_fd_ >= 0) ::close(lock_fd_);
}

void Vault::lock(const fs::path& dir, const std::string& user) {
  const fs::path lock_path = dir / user / "lock";
  const int fd = ::open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (fd < 0) fail_errno("cannot create the vault lock");
  if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
    ::close(fd);
    throw VaultError("this account is already open in another bridge; close that one first");
  }
  lock_fd_ = fd;
}

fs::path Vault::path_for(const fs::path& dir, const std::string& user) { return dir / user / "vault.json"; }

bool Vault::exists(const fs::path& dir, const std::string& user) {
  return valid_username(user) && fs::exists(path_for(dir, user));
}

Vault Vault::create(const fs::path& dir, const std::string& user, const std::string& passphrase,
                    const std::string& kdf_profile, const json& state) {
  if (!valid_username(user)) throw VaultError("invalid username");
  if (passphrase.size() < MIN_PASSPHRASE) throw VaultError("passphrase must be at least 8 characters");
  if (passphrase.size() > MAX_PASSPHRASE) throw VaultError("passphrase is too long");
  if (exists(dir, user)) throw VaultError("a vault for " + user + " already exists");

  fs::create_directories(dir / user);
  fs::permissions(dir / user, fs::perms::owner_all, fs::perm_options::replace);

  PwhashParams params;
  try {
    params = pwhash_profile(kdf_profile);
  } catch (const std::invalid_argument&) {
    throw VaultError("unknown key-derivation profile: " + kdf_profile);
  }
  const Bytes salt = random_bytes(PWHASH_SALT_SIZE);

  Vault v;
  v.lock(dir, user);
  v.path_ = path_for(dir, user);
  v.user_ = user;
  v.kdf_ = {{"alg", "argon2id13"}, {"salt", b64(salt)}, {"ops", params.ops}, {"mem", params.mem_bytes}};
  v.ad_ = vault_ad(user, v.kdf_);
  v.key_ = argon2id(passphrase, salt, params);
  v.save(state);
  return v;
}

std::pair<Vault, json> Vault::open(const fs::path& dir, const std::string& user, const std::string& passphrase) {
  if (!exists(dir, user)) throw VaultError("no vault for " + user);
  Vault v;
  // lock before reading, never decrypt a vault another process is writing
  v.lock(dir, user);
  std::ifstream in(path_for(dir, user));
  std::stringstream ss;
  ss << in.rdbuf();
  const json file = json::parse(ss.str(), nullptr, false);
  if (file.is_discarded() || file.value("format", "") != "pqs-vault" || file.value("v", 0) != 1) {
    throw VaultError("vault file is corrupt or from an unknown version");
  }
  if (file.value("user", "") != user) throw VaultError("vault belongs to a different user");

  v.path_ = path_for(dir, user);
  v.user_ = user;
  v.kdf_ = file.at("kdf");
  if (v.kdf_.value("alg", "") != "argon2id13") throw VaultError("unsupported vault key derivation");
  const std::uint64_t ops = v.kdf_.at("ops"), mem = v.kdf_.at("mem");
  // cap kdf params from the file, a tampered one could make us burn cpu and ram
  if (ops < crypto_pwhash_OPSLIMIT_MIN || ops > 64 || mem < crypto_pwhash_MEMLIMIT_MIN || mem > (std::uint64_t{4} << 30)) {
    throw VaultError("vault key-derivation parameters are out of range");
  }
  v.ad_ = vault_ad(user, v.kdf_);
  v.key_ = argon2id(passphrase, from_base64(v.kdf_.at("salt").get<std::string>()), {ops, static_cast<std::size_t>(mem)});

  auto plain = aead_open(v.key_, from_base64(file.at("box").get<std::string>()), v.ad_);
  if (!plain) return {std::move(v), json::object()};
  json state = json::parse(plain->begin(), plain->end(), nullptr, false);
  if (state.is_discarded()) throw VaultError("vault contents are corrupt");
  return {std::move(v), std::move(state)};
}

void Vault::save(const json& state) const {
  std::string plain = state.dump();
  const Bytes box = aead_seal(key_, view(plain), ad_);
  sodium_memzero(plain.data(), plain.size());
  const json file = {{"format", "pqs-vault"}, {"v", 1}, {"user", user_}, {"kdf", kdf_}, {"box", b64(box)}};
  atomic_write(path_, file.dump());
}

}
