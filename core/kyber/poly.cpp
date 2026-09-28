#include "kyber/poly.hpp"

namespace pqs::kyber {

Poly add(const Poly& a, const Poly& b) {
  Poly r;
  for (int i = 0; i < N; ++i) r[i] = mod_add(a[i], b[i]);
  return r;
}

Poly sub(const Poly& a, const Poly& b) {
  Poly r;
  for (int i = 0; i < N; ++i) r[i] = mod_sub(a[i], b[i]);
  return r;
}

// alg 9, 7 butterfly layers, result is f mod the 128 quadratic factors of x to the 256 plus 1
void ntt(Poly& f) {
  int i = 1;
  for (int len = 128; len >= 2; len /= 2) {
    for (int start = 0; start < N; start += 2 * len) {
      const std::uint16_t zeta = ZETAS[static_cast<std::size_t>(i++)];
      for (int j = start; j < start + len; ++j) {
        const std::uint16_t t = mod_mul(zeta, f[j + len]);
        f[j + len] = mod_sub(f[j], t);
        f[j] = mod_add(f[j], t);
      }
    }
  }
}

// alg 10, same butterflies backwards, then scale by 128 inverse mod q which is 3303
void ntt_inverse(Poly& f) {
  int i = 127;
  for (int len = 2; len <= 128; len *= 2) {
    for (int start = 0; start < N; start += 2 * len) {
      const std::uint16_t zeta = ZETAS[static_cast<std::size_t>(i--)];
      for (int j = start; j < start + len; ++j) {
        const std::uint16_t t = f[j];
        f[j] = mod_add(t, f[j + len]);
        f[j + len] = mod_mul(zeta, mod_sub(f[j + len], t));
      }
    }
  }
  
}

// alg 11, splits into 128 degree 1 products mod x squared minus gamma i
Poly multiply_ntts(const Poly& f, const Poly& g) {
  Poly h;
  for (int i = 0; i < 128; ++i) {
    const std::uint16_t a0 = f[2 * i], a1 = f[2 * i + 1];
    const std::uint16_t b0 = g[2 * i], b1 = g[2 * i + 1];
    const std::uint16_t gamma = GAMMAS[static_cast<std::size_t>(i)];
    // alg 12 basecasemultiply, a0 plus a1 x times b0 plus b1 x, mod x squared minus gamma
    h[2 * i] = mod_add(mod_mul(a0, b0), mod_mul(mod_mul(a1, b1), gamma));
    h[2 * i + 1] = mod_add(mod_mul(a0, b1), mod_mul(a1, b0));
  }
  return h;
}

}
