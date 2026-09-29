#include "kyber/encode.hpp"

#include <cstring>

namespace pqs::kyber {

void byte_encode(int d, const Poly& f, std::uint8_t* out) {
  // bit j of coeff i -> output bit i times d plus j, alg 4 and 5
  std::memset(out, 0, static_cast<std::size_t>(32 * d));
  for (int i = 0; i < N; ++i) {
    for (int j = 0; j < d; ++j) {
      const int bit = (f[i] >> j) & 1;
      const int pos = i * d + j;
      out[pos / 8] = static_cast<std::uint8_t>(out[pos / 8] | (bit << (pos % 8)));
    }
  }
}

Bytes byte_encode(int d, const Poly& f) {
  Bytes out(static_cast<std::size_t>(32 * d));
  byte_encode(d, f, out.data());
  return out;
}

Poly byte_decode(int d, const std::uint8_t* in) {
  Poly f;
  for (int i = 0; i < N; ++i) {
    std::uint32_t value = 0;
    for (int j = 0; j < d; ++j) {
      const int pos = i * d + j;
      value |= static_cast<std::uint32_t>((in[pos / 8] >> (pos % 8)) & 1) << j;
    }
    // d 12 can give values at or above q, spec reduces mod q, a bad ek is caught by the modulus check
    f[i] = static_cast<std::uint16_t>(d == 12 ? value % Q : value);
  }
  return f;
}

Poly compress(int d, const Poly& f) {
  Poly r;
  for (int i = 0; i < N; ++i) r[i] = compress(d, f[i]);
  return r;
}

Poly decompress(int d, const Poly& f) {
  Poly r;
  for (int i = 0; i < N; ++i) r[i] = decompress(d, f[i]);
  return r;
}

}
