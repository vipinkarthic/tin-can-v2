#include "kyber/kpke.hpp"

#include "crypto/hash.hpp"
#include "kyber/encode.hpp"
#include "kyber/sample.hpp"

#include <vector>

namespace pqs::kyber {
namespace {

using PolyVec = std::vector<Poly>;

// a hat i j is samplentt of rho, j, i, stored row major as a at i times k plus j
PolyVec generate_matrix(const Params& p, ByteView rho) {
  PolyVec a(static_cast<std::size_t>(p.k * p.k));
  for (int i = 0; i < p.k; ++i)
    for (int j = 0; j < p.k; ++j)
      a[static_cast<std::size_t>(i * p.k + j)] = sample_ntt(rho, static_cast<std::uint8_t>(j), static_cast<std::uint8_t>(i));
  return a;
}

// bumps the shared prf counter k times, the specs n
PolyVec sample_noise_vec(const Params& p, int eta, ByteView seed, std::uint8_t& counter) {
  PolyVec v(static_cast<std::size_t>(p.k));
  for (auto& poly : v) poly = sample_poly_cbd(eta, prf(eta, seed, counter++));
  return v;
}

// sum of a j times b j, both already in ntt form
Poly dot_ntt(const PolyVec& a, const PolyVec& b) {
  Poly acc;
  for (std::size_t j = 0; j < a.size(); ++j) acc = add(acc, multiply_ntts(a[j], b[j]));
  return acc;
}

}

PkeKeyPair kpke_keygen(const Params& p, ByteView d) {
  // rho and sigma come from g of d and k, rho seeds the public matrix, sigma the secret noise
  const std::uint8_t k_byte = static_cast<std::uint8_t>(p.k);
  const Bytes g = sha3_512({d, ByteView(&k_byte, 1)});
  const ByteView rho(g.data(), 32), sigma(g.data() + 32, 32);

  const PolyVec a_hat = generate_matrix(p, rho);
  std::uint8_t counter = 0;
  PolyVec s = sample_noise_vec(p, p.eta1, sigma, counter);
  PolyVec e = sample_noise_vec(p, p.eta1, sigma, counter);
  for (auto& poly : s) ntt(poly);
  for (auto& poly : e) ntt(poly);

  // t hat is a hat times s hat plus e hat
  PkeKeyPair keys;
  keys.ek.resize(p.ek_size());
  keys.dk.resize(static_cast<std::size_t>(384 * p.k));
  for (int i = 0; i < p.k; ++i) {
    PolyVec row(a_hat.begin() + i * p.k, a_hat.begin() + (i + 1) * p.k);
    const Poly t_i = add(dot_ntt(row, s), e[static_cast<std::size_t>(i)]);
    byte_encode(12, t_i, keys.ek.data() + 384 * i);
    byte_encode(12, s[static_cast<std::size_t>(i)], keys.dk.data() + 384 * i);
  }
  std::copy(rho.begin(), rho.end(), keys.ek.begin() + 384 * p.k);
  return keys;
}

Bytes kpke_encrypt(const Params& p, ByteView ek, ByteView m, ByteView r) {
  PolyVec t_hat(static_cast<std::size_t>(p.k));
  for (int i = 0; i < p.k; ++i) t_hat[static_cast<std::size_t>(i)] = byte_decode(12, ek.data() + 384 * i);
  const ByteView rho = ek.subspan(static_cast<std::size_t>(384 * p.k), 32);
  const PolyVec a_hat = generate_matrix(p, rho);

  std::uint8_t counter = 0;
  PolyVec y = sample_noise_vec(p, p.eta1, r, counter);
  PolyVec e1 = sample_noise_vec(p, p.eta2, r, counter);
  const Poly e2 = sample_poly_cbd(p.eta2, prf(p.eta2, r, counter));
  for (auto& poly : y) ntt(poly);

  Bytes c(p.ct_size());
  // u is inverse ntt of a hat transpose times y hat, plus e1
  for (int i = 0; i < p.k; ++i) {
    PolyVec column(static_cast<std::size_t>(p.k));
    for (int j = 0; j < p.k; ++j) column[static_cast<std::size_t>(j)] = a_hat[static_cast<std::size_t>(j * p.k + i)];
    Poly u_i = dot_ntt(column, y);
    ntt_inverse(u_i);
    u_i = add(u_i, e1[static_cast<std::size_t>(i)]);
    byte_encode(p.du, compress(p.du, u_i), c.data() + 32 * p.du * i);
  }
  // v is inverse ntt of t hat transpose times y hat, plus e2 plus mu, mu puts each message bit at 0 or q over 2
  const Poly mu = decompress(1, byte_decode(1, m.data()));
  Poly v = dot_ntt(t_hat, y);
  ntt_inverse(v);
  v = add(add(v, e2), mu);
  byte_encode(p.dv, compress(p.dv, v), c.data() + 32 * p.du * p.k);
  return c;
}

Bytes kpke_decrypt(const Params& p, ByteView dk, ByteView c) {
  PolyVec u(static_cast<std::size_t>(p.k)), s_hat(static_cast<std::size_t>(p.k));
  for (int i = 0; i < p.k; ++i) {
    u[static_cast<std::size_t>(i)] = decompress(p.du, byte_decode(p.du, c.data() + 32 * p.du * i));
    s_hat[static_cast<std::size_t>(i)] = byte_decode(12, dk.data() + 384 * i);
  }
  const Poly v = decompress(p.dv, byte_decode(p.dv, c.data() + 32 * p.du * p.k));

  // w is v minus inverse ntt of s hat transpose times ntt of u, so message plus small noise
  for (auto& poly : u) ntt(poly);
  Poly su = dot_ntt(s_hat, u);
  ntt_inverse(su);
  const Poly w = sub(v, su);

  // round each coeff to 0 or q over 2, one message bit each
  return byte_encode(1, compress(1, w));
}

}
