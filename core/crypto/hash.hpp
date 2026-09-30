#pragma once

#include "crypto/bytes.hpp"

#include <initializer_list>

struct evp_md_ctx_st;

namespace pqs {

// args get concatenated, so sha3 256 of a, b hashes a then b
Bytes sha3_256(std::initializer_list<ByteView> parts);
Bytes sha3_512(std::initializer_list<ByteView> parts);
Bytes shake256(std::initializer_list<ByteView> parts, std::size_t out_len);

// streaming xof, rejection sampling needs an unknown number of bytes
class Shake128 {
 public:
  explicit Shake128(std::initializer_list<ByteView> parts);
  ~Shake128();
  Shake128(const Shake128&) = delete;
  Shake128& operator=(const Shake128&) = delete;

  void squeeze(std::uint8_t* out, std::size_t n);

 private:
  evp_md_ctx_st* ctx_;
};

}
