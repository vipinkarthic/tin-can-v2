#pragma once
// fips 203 sections 6 and 7, the internal ones are deterministic, only for nist vectors and openssl cross checks

#include "crypto/bytes.hpp"
#include "kyber/params.hpp"

namespace pqs::kyber {

struct KeyPair {
  Bytes ek;
  // dk pke, ek, h of ek, z
  Bytes dk;
};

struct Encapsulation {
  // k, 32 bytes
  Bytes shared_key;
  Bytes ciphertext;
};

// fips 203 alg 16
KeyPair keygen_internal(const Params& p, ByteView d, ByteView z);
// fips 203 alg 17
Encapsulation encaps_internal(const Params& p, ByteView ek, ByteView m);
// fips 203 alg 18
Bytes decaps_internal(const Params& p, ByteView dk, ByteView c);

// fips 203 alg 19
KeyPair keygen(const Params& p);
// fips 203 alg 20
Encapsulation encaps(const Params& p, ByteView ek);
// fips 203 alg 21
Bytes decaps(const Params& p, ByteView dk, ByteView c);

// fips 203 section 7.2 and 7.3 input checks, encaps and decaps run them and throw
bool check_encaps_key(const Params& p, ByteView ek);
// length and hash check
bool check_decaps_key(const Params& p, ByteView dk);
// length check only
bool check_ciphertext(const Params& p, ByteView c);

}
