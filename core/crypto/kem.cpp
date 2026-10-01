#include "crypto/kem.hpp"

#include "kyber/mlkem.hpp"

namespace pqs {

// no input checks here, kyber encaps and decaps already do the fips 203 ones
KemKeyPair kem_keygen() {
  kyber::KeyPair k = kyber::keygen(kyber::MLKEM768);
  return {std::move(k.ek), std::move(k.dk)};
}

KemEncapsulation kem_encaps(ByteView pk) {
  kyber::Encapsulation e = kyber::encaps(kyber::MLKEM768, pk);
  return {std::move(e.shared_key), std::move(e.ciphertext)};
}

Bytes kem_decaps(ByteView sk, ByteView ciphertext) { return kyber::decaps(kyber::MLKEM768, sk, ciphertext); }

}
