#pragma once

#include "crypto/bytes.hpp"

namespace pqs {

inline Bytes random_bytes(std::size_t n) {
  Bytes out(n);
  randombytes_buf(out.data(), out.size());
  return out;
}

}
