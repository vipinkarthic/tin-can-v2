#pragma once

namespace pqs {

// call once at startup before any other pqs call, throws if libsodium wont init
void init();

}
