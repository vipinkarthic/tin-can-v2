#pragma once
// fips 203 section 4.3, coeffs stay fully reduced below q and nothing branches on them, timing

#include "kyber/params.hpp"

#include <sodium.h>

#include <array>
#include <cstdint>

namespace pqs::kyber {

inline std::uint16_t mod_add(std::uint16_t a, std::uint16_t b) {
  // r is between minus q and q, add q back if negative without a branch
  std::int32_t r = std::int32_t{a} + b - Q;
  r += (r >> 31) & Q;
  return static_cast<std::uint16_t>(r);
}

inline std::uint16_t mod_sub(std::uint16_t a, std::uint16_t b) {
  std::int32_t r = std::int32_t{a} - b;
  r += (r >> 31) & Q;
  return static_cast<std::uint16_t>(r);
}

// q is constant so mod q compiles to multiply and shift, not a variable time div
inline std::uint16_t mod_mul(std::uint16_t a, std::uint16_t b) {
  return static_cast<std::uint16_t>((std::uint32_t{a} * b) % Q);
}

// zeta 17, the primitive 256th root of unity mod q

constexpr std::uint8_t bit_rev7(std::uint8_t x) {
  std::uint8_t r = 0;
  for (int i = 0; i < 7; ++i) r |= static_cast<std::uint8_t>(((x >> i) & 1) << (6 - i));
  return r;
}

constexpr std::uint16_t pow_mod(std::uint32_t base, std::uint32_t exp) {
  std::uint32_t r = 1;
  base %= Q;
  while (exp) {
    if (exp & 1) r = r * base % Q;
    base = base * base % Q;
    exp >>= 1;
  }
  return static_cast<std::uint16_t>(r);
}

// zetas i is zeta to the bitrev7 of i, for ntt and inverse ntt, fips 203 appendix a
inline constexpr std::array<std::uint16_t, 128> ZETAS = [] {
  std::array<std::uint16_t, 128> z{};
  for (int i = 0; i < 128; ++i) z[i] = pow_mod(17, bit_rev7(static_cast<std::uint8_t>(i)));
  return z;
}();

// gammas i is zeta to the 2 times bitrev7 of i plus 1, for multiplyntts
inline constexpr std::array<std::uint16_t, 128> GAMMAS = [] {
  std::array<std::uint16_t, 128> g{};
  for (int i = 0; i < 128; ++i) g[i] = pow_mod(17, 2u * bit_rev7(static_cast<std::uint8_t>(i)) + 1);
  return g;
}();

struct Poly {
  std::array<std::uint16_t, N> c{};

  Poly() = default;
  Poly(const Poly&) = default;
  Poly& operator=(const Poly&) = default;
  // wipe on destroy, polys often hold secrets
  ~Poly() { sodium_memzero(c.data(), sizeof(c)); }

  std::uint16_t& operator[](int i) { return c[static_cast<std::size_t>(i)]; }
  std::uint16_t operator[](int i) const { return c[static_cast<std::size_t>(i)]; }
};

Poly add(const Poly& a, const Poly& b);
Poly sub(const Poly& a, const Poly& b);

// fips 203 alg 9, in place
void ntt(Poly& f);
// fips 203 alg 10, in place
void ntt_inverse(Poly& f);
// fips 203 alg 11 plus alg 12
Poly multiply_ntts(const Poly& f, const Poly& g);

}
