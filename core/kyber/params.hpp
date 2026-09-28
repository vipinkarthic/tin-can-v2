#pragma once
// fips 203 section 8 table 2, app only uses 768, all three kept so every nist vector can be checked

#include <cstddef>
#include <string_view>

namespace pqs::kyber {

inline constexpr int N = 256;
inline constexpr int Q = 3329;

struct Params {
  // also used as the openssl algorithm name
  std::string_view name;
  // module rank
  int k;
  // noise width for s, e, y
  int eta1;
  // noise width for e1, e2
  int eta2;
  // ct bits per coeff of u
  int du;
  // ct bits per coeff of v
  int dv;

  // sizes in bytes, fips 203 table 3
  constexpr std::size_t ek_size() const { return 384 * k + 32; }
  constexpr std::size_t dk_size() const { return 768 * k + 96; }
  constexpr std::size_t ct_size() const { return 32 * (du * k + dv); }
};

inline constexpr Params MLKEM512{"ML-KEM-512", 2, 3, 2, 10, 4};
inline constexpr Params MLKEM768{"ML-KEM-768", 3, 2, 2, 10, 4};
inline constexpr Params MLKEM1024{"ML-KEM-1024", 4, 2, 2, 11, 5};

// d, z and m are each 32 bytes
inline constexpr std::size_t SEED_SIZE = 32;

}
