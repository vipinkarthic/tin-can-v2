#include "kyber/sample.hpp"

#include "crypto/hash.hpp"

#include <stdexcept>

namespace pqs::kyber {

Poly sample_ntt(ByteView rho, std::uint8_t j, std::uint8_t i) {
  const std::uint8_t idx[2] = {j, i};
  Shake128 xof({rho, ByteView(idx, 2)});
  Poly a;
  int n = 0;
  while (n < N) {
    std::uint8_t c[3];
    xof.squeeze(c, 3);
    // 3 bytes -> two 12 bit candidates, keep the ones below q
    const std::uint16_t d1 = static_cast<std::uint16_t>(c[0] + 256 * (c[1] & 0x0F));
    const std::uint16_t d2 = static_cast<std::uint16_t>((c[1] >> 4) + 16 * c[2]);
    if (d1 < Q) a[n++] = d1;
    if (d2 < Q && n < N) a[n++] = d2;
  }
  return a;
}

Poly sample_poly_cbd(int eta, ByteView bytes) {
  if (bytes.size() != static_cast<std::size_t>(64 * eta)) throw std::invalid_argument("CBD input has wrong length");
  auto bit = [&](int pos) -> std::uint16_t { return (bytes[static_cast<std::size_t>(pos / 8)] >> (pos % 8)) & 1; };
  Poly f;
  for (int i = 0; i < N; ++i) {
    std::uint16_t x = 0, y = 0;
    for (int j = 0; j < eta; ++j) {
      x = static_cast<std::uint16_t>(x + bit(2 * i * eta + j));
      y = static_cast<std::uint16_t>(y + bit(2 * i * eta + eta + j));
    }
    // x minus y is between minus eta and eta, stored mod q
    f[i] = mod_sub(x, y);
  }
  return f;
}

Bytes prf(int eta, ByteView s, std::uint8_t b) {
  return shake256({s, ByteView(&b, 1)}, static_cast<std::size_t>(64 * eta));
}

}
