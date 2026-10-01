#pragma once
// test and bench reference only, seed d then z 64 bytes and m 32 bytes make keygen and encaps deterministic

#include "crypto/bytes.hpp"
#include "kyber/mlkem.hpp"

#include <string_view>

namespace pqs::openssl {

kyber::KeyPair mlkem_keygen(std::string_view alg, ByteView seed = {});
kyber::Encapsulation mlkem_encaps(std::string_view alg, ByteView ek, ByteView m = {});
Bytes mlkem_decaps(std::string_view alg, ByteView dk, ByteView c);

}
