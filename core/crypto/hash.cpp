#include "crypto/hash.hpp"

#include <openssl/evp.h>

#include <memory>
#include <stdexcept>

namespace pqs {
namespace {

struct CtxFree { void operator()(EVP_MD_CTX* c) const { EVP_MD_CTX_free(c); } };
using MdCtx = std::unique_ptr<EVP_MD_CTX, CtxFree>;

MdCtx start(const EVP_MD* md, std::initializer_list<ByteView> parts) {
  MdCtx ctx(EVP_MD_CTX_new());
  if (!ctx || EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) throw std::runtime_error("digest init failed");
  for (auto p : parts) {
    if (EVP_DigestUpdate(ctx.get(), p.data(), p.size()) != 1) throw std::runtime_error("digest update failed");
  }
  return ctx;
}

Bytes fixed(const EVP_MD* md, std::initializer_list<ByteView> parts) {
  auto ctx = start(md, parts);
  Bytes out(static_cast<std::size_t>(EVP_MD_get_size(md)));
  unsigned int len = 0;
  if (EVP_DigestFinal_ex(ctx.get(), out.data(), &len) != 1 || len != out.size()) {
    throw std::runtime_error("digest final failed");
  }
  return out;
}

}

Bytes sha3_256(std::initializer_list<ByteView> parts) { return fixed(EVP_sha3_256(), parts); }
Bytes sha3_512(std::initializer_list<ByteView> parts) { return fixed(EVP_sha3_512(), parts); }

Bytes shake256(std::initializer_list<ByteView> parts, std::size_t out_len) {
  auto ctx = start(EVP_shake256(), parts);
  Bytes out(out_len);
  if (EVP_DigestFinalXOF(ctx.get(), out.data(), out.size()) != 1) throw std::runtime_error("shake256 failed");
  return out;
}

Shake128::Shake128(std::initializer_list<ByteView> parts) : ctx_(start(EVP_shake128(), parts).release()) {}

Shake128::~Shake128() { EVP_MD_CTX_free(ctx_); }

void Shake128::squeeze(std::uint8_t* out, std::size_t n) {
  if (EVP_DigestSqueeze(ctx_, out, n) != 1) throw std::runtime_error("shake128 squeeze failed");
}

}
