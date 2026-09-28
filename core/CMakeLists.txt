cmake_minimum_required(VERSION 3.25)
project(tincan_core VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

option(PQS_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)

# deps installed system wide, openssl gives mldsa, sha3, shake and the reference mlkem for tests
find_package(OpenSSL 3.5 REQUIRED)
find_package(PkgConfig REQUIRED)
# xchacha20 poly1305, hmac, argon2id, randomness
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
find_package(nlohmann_json 3.11 REQUIRED)

add_compile_options(-Wall -Wextra -Wpedantic)
if(PQS_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

# shared by the sidecar, tests and bench
add_library(pqs STATIC
  crypto/init.cpp
  crypto/bytes.cpp
  crypto/hash.cpp
  crypto/openssl_mlkem.cpp
  crypto/sig.cpp
  crypto/symmetric.cpp
  crypto/kem.cpp
  kyber/poly.cpp
  kyber/encode.cpp
  kyber/sample.cpp
  kyber/kpke.cpp
  kyber/mlkem.cpp
  protocol/identity.cpp
  protocol/contacts.cpp
  protocol/ratchet.cpp
  protocol/dm.cpp
  protocol/vault.cpp
  protocol/client.cpp
)
target_include_directories(pqs PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pqs PUBLIC OpenSSL::Crypto PkgConfig::SODIUM nlohmann_json::nlohmann_json)

# json lines sidecar, spawned by the node bridge and server
add_executable(pqs-core main.cpp)
target_link_libraries(pqs-core PRIVATE pqs)

# bench lives outside the delivered folder, only build it if its there
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/../bench/bench.cpp)
  add_executable(pqs-bench ${CMAKE_CURRENT_SOURCE_DIR}/../bench/bench.cpp)
  target_link_libraries(pqs-bench PRIVATE pqs)
  target_compile_definitions(pqs-bench PRIVATE PQS_BUILD_TYPE="${CMAKE_BUILD_TYPE}")
endif()

# tests arent in the delivered folder either, skip if missing
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  find_package(GTest REQUIRED)
  enable_testing()
  add_executable(pqs-tests
    tests/test_toolchain.cpp
    tests/test_kyber.cpp
    tests/test_crypto.cpp
    tests/test_protocol.cpp
  )
  target_link_libraries(pqs-tests PRIVATE pqs GTest::gtest_main)
  target_compile_definitions(pqs-tests PRIVATE PQS_TEST_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors")
  include(GoogleTest)
  gtest_discover_tests(pqs-tests)
endif()
