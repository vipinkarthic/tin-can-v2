#pragma once
// kpke, fips 203 section 5, is only ind cpa, never use it directly, mlkem wraps it with fo

#include "crypto/bytes.hpp"
#include "kyber/params.hpp"

namespace pqs::kyber {

struct PkeKeyPair {
  // byteencode12 of t hat then rho, 384 times k plus 32 bytes
  Bytes ek;
  // byteencode12 of s hat, 384 times k bytes
  Bytes dk;
};

// fips 203 alg 13
PkeKeyPair kpke_keygen(const Params& p, ByteView d);
// fips 203 alg 14
Bytes kpke_encrypt(const Params& p, ByteView ek, ByteView m, ByteView r);
// fips 203 alg 15
Bytes kpke_decrypt(const Params& p, ByteView dk, ByteView c);

}
