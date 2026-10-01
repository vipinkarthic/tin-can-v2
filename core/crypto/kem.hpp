#pragma once
// mlkem 768 from our own core kyber, openssls mlkem is only a reference for tests and bench

#include "crypto/bytes.hpp"

namespace pqs {

inline constexpr std::size_t KEM_PUBLIC_KEY_SIZE = 1184;
inline constexpr std::size_t KEM_SECRET_KEY_SIZE = 2400;
inline constexpr std::size_t KEM_CIPHERTEXT_SIZE = 1088;

struct KemKeyPair {
  Bytes pk;
  Bytes sk;
};

struct KemEncapsulation {
  Bytes shared_key;
  Bytes ciphertext;
};

KemKeyPair kem_keygen();
// throws invalid argument on a bad key
KemEncapsulation kem_encaps(ByteView pk);
// throws invalid argument on bad input
Bytes kem_decaps(ByteView sk, ByteView ciphertext);

}
