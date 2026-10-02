#pragma once
// mk is hmac of ck with 0x01, next ck is hmac of ck with 0x02, old ck is overwritten so forward secrecy

#include "protocol/common.hpp"

#include <map>
#include <utility>

namespace pqs::protocol {

// max counter jump in one go
inline constexpr std::uint32_t MAX_SKIP = 1000;
// past this the oldest skipped keys get dropped
inline constexpr std::size_t MAX_STORED_SKIPPED = 2000;

struct SendChain {
  Bytes ck;
  // next counter to send
  std::uint32_t n = 0;
};

struct RecvChain {
  Bytes ck;
  // next counter expected
  std::uint32_t n = 0;
  // counter -> mk, for out of order msgs
  std::map<std::uint32_t, Bytes> skipped;
};

// returns counter and mk
std::pair<std::uint32_t, Bytes> ratchet_send(SendChain& chain);

// doesnt touch chain, commit next only after decrypt works, so forgeries cant move it
// throws protocol error on replays or counters too far ahead
Bytes ratchet_recv(const RecvChain& chain, std::uint32_t n, RecvChain& next);

json send_chain_to_json(const SendChain& c);
SendChain send_chain_from_json(const json& j);
json recv_chain_to_json(const RecvChain& c);
RecvChain recv_chain_from_json(const json& j);

}
