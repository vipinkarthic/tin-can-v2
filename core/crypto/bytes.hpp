#pragma once
// bytes wipes itself on free, vector regrowth too, so key material never lingers on the heap

#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace pqs {

template <class T>
struct ZeroingAllocator {
  using value_type = T;
  ZeroingAllocator() noexcept = default;
  template <class U>
  ZeroingAllocator(const ZeroingAllocator<U>&) noexcept {}

  T* allocate(std::size_t n) { return std::allocator<T>{}.allocate(n); }
  void deallocate(T* p, std::size_t n) noexcept {
    sodium_memzero(p, n * sizeof(T));
    std::allocator<T>{}.deallocate(p, n);
  }
  template <class U>
  bool operator==(const ZeroingAllocator<U>&) const noexcept { return true; }
};

using Bytes = std::vector<std::uint8_t, ZeroingAllocator<std::uint8_t>>;
using ByteView = std::span<const std::uint8_t>;

inline ByteView view(std::string_view s) {
  return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}
inline Bytes to_bytes(ByteView v) { return Bytes(v.begin(), v.end()); }
inline Bytes to_bytes(std::string_view s) { return to_bytes(view(s)); }

inline Bytes concat(std::initializer_list<ByteView> parts) {
  std::size_t n = 0;
  for (auto p : parts) n += p.size();
  Bytes out;
  out.reserve(n);
  for (auto p : parts) out.insert(out.end(), p.begin(), p.end());
  return out;
}

// 4 byte big endian length prefix so alice plus bob cant look like alic plus ebob in a transcript
inline void append_field(Bytes& out, ByteView field) {
  const auto n = static_cast<std::uint32_t>(field.size());
  for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<std::uint8_t>(n >> shift));
  out.insert(out.end(), field.begin(), field.end());
}
inline void append_field(Bytes& out, std::string_view field) { append_field(out, view(field)); }

// constant time, length isnt secret so a size mismatch can bail early
inline bool ct_equal(ByteView a, ByteView b) {
  return a.size() == b.size() && sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string to_hex(ByteView v);
// throws invalid argument
Bytes from_hex(std::string_view hex);
std::string to_base64(ByteView v);
// throws invalid argument
Bytes from_base64(std::string_view b64);

}
