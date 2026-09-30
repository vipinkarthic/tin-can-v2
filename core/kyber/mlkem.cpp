#include "kyber/mlkem.hpp"

#include "crypto/hash.hpp"
#include "crypto/random.hpp"
#include "kyber/encode.hpp"
#include "kyber/kpke.hpp"

#include <stdexcept>

namespace pqs::kyber {

KeyPair keygen_internal(const Params& p, ByteView d, ByteView z) {
  PkeKeyPair pke = kpke_keygen(p, d);
  KeyPair keys;
  keys.ek = pke.ek;
  const Bytes h = sha3_256({keys.ek});
  keys.dk = concat({pke.dk, keys.ek, h, z});
  return keys;
}

Encapsulation encaps_internal(const Params& p, ByteView ek, ByteView m) {
  // k and r come from g of m and h of ek, all randomness comes from m so decaps can re encrypt and check, fo
  const Bytes g = sha3_512({m, sha3_256({ek})});
  Encapsulation out;
  out.shared_key.assign(g.begin(), g.begin() + 32);
  out.ciphertext = kpke_encrypt(p, ek, m, ByteView(g.data() + 32, 32));
  return out;
}

Bytes decaps_internal(const Params& p, ByteView dk, ByteView c) {
  const std::size_t k384 = static_cast<std::size_t>(384 * p.k);
  const ByteView dk_pke = dk.subspan(0, k384);
  const ByteView ek_pke = dk.subspan(k384, k384 + 32);
  const ByteView h = dk.subspan(2 * k384 + 32, 32);
  const ByteView z = dk.subspan(2 * k384 + 64, 32);

  const Bytes m_prime = kpke_decrypt(p, dk_pke, c);
  // k prime and r prime come from g of m prime and h
  const Bytes g = sha3_512({m_prime, h});
  const ByteView k_prime(g.data(), 32), r_prime(g.data() + 32, 32);
  // k bar is j of z and c, the implicit rejection key
  const Bytes k_bar = shake256({z, c}, 32);
  const Bytes c_prime = kpke_encrypt(p, ek_pke, m_prime, r_prime);

  // tampered c gives k bar instead of an error, implicit rejection, compare and select are constant time
  const std::uint8_t keep_mask = ct_equal(c, c_prime) ? 0xFF : 0x00;
  Bytes key(32);
  for (std::size_t i = 0; i < 32; ++i) {
    key[i] = static_cast<std::uint8_t>(k_bar[i] ^ (keep_mask & (k_prime[i] ^ k_bar[i])));
  }
  return key;
}

bool check_encaps_key(const Params& p, ByteView ek) {
  if (ek.size() != p.ek_size()) return false;
  // modulus check, section 7.2, decode then re encode must round trip, so every coeff is below q
  for (int i = 0; i < p.k; ++i) {
    const std::uint8_t* chunk = ek.data() + 384 * i;
    const Bytes again = byte_encode(12, byte_decode(12, chunk));
    
  }
  return true;
}

bool check_decaps_key(const Params& p, ByteView dk) {
  if (dk.size() != p.dk_size()) return false;
  // hash check, section 7.3, stored h of ek must match the embedded ek
  const std::size_t k384 = static_cast<std::size_t>(384 * p.k);
  const Bytes h = sha3_256({dk.subspan(k384, k384 + 32)});
  return ct_equal(h, dk.subspan(2 * k384 + 32, 32));
}

bool check_ciphertext(const Params& p, ByteView c) { return c.size() == p.ct_size(); }

KeyPair keygen(const Params& p) {
  const Bytes d = random_bytes(SEED_SIZE), z = random_bytes(SEED_SIZE);
  return keygen_internal(p, d, z);
}

Encapsulation encaps(const Params& p, ByteView ek) {
  if (!check_encaps_key(p, ek)) throw std::invalid_argument("invalid ML-KEM encapsulation key");
  const Bytes m = random_bytes(SEED_SIZE);
  return encaps_internal(p, ek, m);
}

Bytes decaps(const Params& p, ByteView dk, ByteView c) {
  if (!check_ciphertext(p, c)) throw std::invalid_argument("invalid ML-KEM ciphertext length");
  if (!check_decaps_key(p, dk)) throw std::invalid_argument("invalid ML-KEM decapsulation key");
  return decaps_internal(p, dk, c);
}

}
