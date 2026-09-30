#include "crypto/bytes.hpp"

#include <stdexcept>

namespace pqs {

std::string to_hex(ByteView v) {
  std::string out(v.size() * 2 + 1, '\0');
  sodium_bin2hex(out.data(), out.size(), v.data(), v.size());
  out.pop_back();
  return out;
}

Bytes from_hex(std::string_view hex) {
  Bytes out(hex.size() / 2);
  std::size_t len = 0;
  const char* end = nullptr;
  if (hex.size() % 2 != 0 ||
      sodium_hex2bin(out.data(), out.size(), hex.data(), hex.size(), nullptr, &len, &end) != 0 ||
      end != hex.data() + hex.size()) {
    throw std::invalid_argument("invalid hex string");
  }
  out.resize(len);
  return out;
}

std::string to_base64(ByteView v) {
  constexpr int variant = sodium_base64_VARIANT_ORIGINAL;
  std::string out(sodium_base64_encoded_len(v.size(), variant), '\0');
  sodium_bin2base64(out.data(), out.size(), v.data(), v.size(), variant);
  // drop sodiums trailing nul
  out.pop_back();
  return out;
}

Bytes from_base64(std::string_view b64) {
  Bytes out(b64.size() / 4 * 3 + 3);
  std::size_t len = 0;
  const char* end = nullptr;
  if (sodium_base642bin(out.data(), out.size(), b64.data(), b64.size(), nullptr, &len, &end,
                        sodium_base64_VARIANT_ORIGINAL) != 0 ||
      end != b64.data() + b64.size()) {
    throw std::invalid_argument("invalid base64 string");
  }
  out.resize(len);
  return out;
}

}
