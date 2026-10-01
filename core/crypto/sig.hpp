#pragma once
// mldsa 65, fips 204, via openssl, signs bundles, dm request and accept, and logins

#include "crypto/bytes.hpp"

namespace pqs {

inline constexpr std::size_t MLDSA65_PUBLIC_KEY_SIZE = 1952;
inline constexpr std::size_t MLDSA65_SIGNATURE_SIZE = 3309;

struct SigKeyPair {
  Bytes pk;
  // openssls raw private key encoding
  Bytes sk;
};

SigKeyPair mldsa_keygen();
Bytes mldsa_sign(ByteView sk, ByteView message);
// never throws on bad input, just returns false
bool mldsa_verify(ByteView pk, ByteView message, ByteView signature);

}
