#include "crypto/init.hpp"

#include <sodium.h>

#include <stdexcept>

namespace pqs {

void init() {
  // 1 means already initialised which is fine, only minus 1 is a failure
  if (sodium_init() < 0) {
    throw std::runtime_error("libsodium initialisation failed");
  }
  // openssl 3 inits itself on first use
}

}
