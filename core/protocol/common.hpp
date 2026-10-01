#pragma once

#include "crypto/bytes.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace pqs::protocol {

using json = nlohmann::json;

inline constexpr int WIRE_VERSION = 1;

// message is safe to show the user and to log
struct ProtocolError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

// every field is length prefixed so different splits cant give the same bytes
class Transcript {
 public:
  explicit Transcript(std::string_view label) { append_field(buf_, label); }
  Transcript& add(ByteView v) { append_field(buf_, v); return *this; }
  Transcript& add(std::string_view s) { append_field(buf_, s); return *this; }
  Transcript& add(const char* s) { return add(std::string_view(s)); }
  Transcript& add(const std::string& s) { return add(std::string_view(s)); }
  Transcript& add(std::uint64_t n) { return add(std::string_view(std::to_string(n))); }
  const Bytes& bytes() const { return buf_; }

 private:
  Bytes buf_;
};

inline std::int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

// missing or wrong typed fields throw protocol error, its untrusted input

inline const json& field(const json& j, const char* key) {
  if (!j.is_object() || !j.contains(key)) throw ProtocolError(std::string("missing field: ") + key);
  return j.at(key);
}

inline std::string str_field(const json& j, const char* key) {
  const json& v = field(j, key);
  if (!v.is_string()) throw ProtocolError(std::string("field must be a string: ") + key);
  return v.get<std::string>();
}

inline std::uint64_t uint_field(const json& j, const char* key) {
  const json& v = field(j, key);
  if (!v.is_number_unsigned() && !(v.is_number_integer() && v.get<std::int64_t>() >= 0)) {
    throw ProtocolError(std::string("field must be a non-negative integer: ") + key);
  }
  return v.get<std::uint64_t>();
}

inline Bytes b64_field(const json& j, const char* key) {
  try {
    return from_base64(str_field(j, key));
  } catch (const std::invalid_argument&) {
    throw ProtocolError(std::string("field is not valid base64: ") + key);
  }
}

inline std::string b64(ByteView v) { return to_base64(v); }

inline void expect_type(const json& env, std::string_view type) {
  if (str_field(env, "type") != type) throw ProtocolError("unexpected envelope type");
  if (!env.contains("v") || env.at("v") != WIRE_VERSION) throw ProtocolError("unsupported protocol version");
}

}
