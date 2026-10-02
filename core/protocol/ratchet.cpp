#include "protocol/ratchet.hpp"

#include "crypto/symmetric.hpp"

namespace pqs::protocol {
namespace {

const std::uint8_t MSG_CONST[1] = {0x01};
const std::uint8_t CHAIN_CONST[1] = {0x02};

Bytes message_key(ByteView ck) { return hmac_sha256(ck, ByteView(MSG_CONST, 1)); }
Bytes next_chain(ByteView ck) { return hmac_sha256(ck, ByteView(CHAIN_CONST, 1)); }

}

std::pair<std::uint32_t, Bytes> ratchet_send(SendChain& chain) {
  Bytes mk = message_key(chain.ck);
  // old ck gets wiped when its buffer is freed, zeroing allocator
  chain.ck = next_chain(chain.ck);
  return {chain.n++, std::move(mk)};
}

Bytes ratchet_recv(const RecvChain& chain, std::uint32_t n, RecvChain& next) {
  next = chain;
  if (n < chain.n) {
    auto it = next.skipped.find(n);
    if (it == next.skipped.end()) throw ProtocolError("message replayed or too old");
    Bytes mk = std::move(it->second);
    next.skipped.erase(it);
    return mk;
  }
  if (n - chain.n > MAX_SKIP) throw ProtocolError("message counter too far ahead");
  // keep keys for skipped msgs so late ones still decrypt
  while (next.n < n) {
    next.skipped[next.n] = message_key(next.ck);
    next.ck = next_chain(next.ck);
    ++next.n;
  }
  while (next.skipped.size() > MAX_STORED_SKIPPED) next.skipped.erase(next.skipped.begin());
  Bytes mk = message_key(next.ck);
  next.ck = next_chain(next.ck);
  ++next.n;
  return mk;
}

json send_chain_to_json(const SendChain& c) { return {{"ck", b64(c.ck)}, {"n", c.n}}; }

SendChain send_chain_from_json(const json& j) {
  return {b64_field(j, "ck"), static_cast<std::uint32_t>(uint_field(j, "n"))};
}

json recv_chain_to_json(const RecvChain& c) {
  json skipped = json::object();
  for (const auto& [n, mk] : c.skipped) skipped[std::to_string(n)] = b64(mk);
  return {{"ck", b64(c.ck)}, {"n", c.n}, {"skipped", skipped}};
}

RecvChain recv_chain_from_json(const json& j) {
  RecvChain c{b64_field(j, "ck"), static_cast<std::uint32_t>(uint_field(j, "n")), {}};
  for (const auto& [n, mk] : field(j, "skipped").items()) {
    c.skipped[static_cast<std::uint32_t>(std::stoul(n))] = from_base64(mk.get<std::string>());
  }
  return c;
}

}
