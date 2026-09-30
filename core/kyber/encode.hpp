#pragma once
// fips 203 section 4.2.1, alg 3 to 6

#include "crypto/bytes.hpp"
#include "kyber/poly.hpp"

namespace pqs::kyber {

// alg 5 byteencode d, 256 d bit ints -> 32 times d bytes, little endian bits
void byte_encode(int d, const Poly& f, std::uint8_t* out);
Bytes byte_encode(int d, const Poly& f);

// alg 6 bytedecode d, values are mod 2 to the d, or mod q when d is 12
Poly byte_decode(int d, const std::uint8_t* in);

// compress d of x is round of 2 to the d over q times x, mod 2 to the d, eq 4.7
inline std::uint16_t compress(int d, std::uint16_t x) {
  // round a over b is floor of 2a plus b over 2b, constant divisor so no variable time div
  const std::uint32_t num = (std::uint32_t{x} << (d + 1)) + Q;
  return static_cast<std::uint16_t>((num / (2 * Q)) & ((1u << d) - 1));
}

// decompress d of y is round of q over 2 to the d times y, eq 4.8
inline std::uint16_t decompress(int d, std::uint16_t y) {
  return static_cast<std::uint16_t>((std::uint32_t{y} * Q + (1u << (d - 1))) >> d);
}

Poly compress(int d, const Poly& f);
Poly decompress(int d, const Poly& f);

}
