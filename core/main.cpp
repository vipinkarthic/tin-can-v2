// sidecar, one json request per stdin line, one json reply per stdout line, stderr is diagnostics only

#include "crypto/init.hpp"
#include "crypto/sig.hpp"
#include "protocol/client.hpp"
#include "protocol/identity.hpp"

#include <nlohmann/json.hpp>

#include <exception>
#include <iostream>
#include <optional>
#include <set>
#include <string>

using json = nlohmann::json;
using namespace pqs;
using namespace pqs::protocol;

namespace {

struct UsageError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

std::optional<Client> g_client;

const json& arg(const json& args, const char* key) {
  if (!args.is_object() || !args.contains(key)) throw UsageError(std::string("missing argument: ") + key);
  return args.at(key);
}
std::string sarg(const json& args, const char* key) {
  const json& v = arg(args, key);
  if (!v.is_string()) throw UsageError(std::string("argument must be a string: ") + key);
  return v.get<std::string>();
}
Bytes b64arg(const json& args, const char* key) {
  try {
    return from_base64(sarg(args, key));
  } catch (const std::invalid_argument&) {
    throw UsageError(std::string("argument is not valid base64: ") + key);
  }
}
Client& client() {
  if (!g_client) throw UsageError("no account is open; use client.create or client.open first");
  return *g_client;
}

json handle(const std::string& cmd, const json& a) {
  // no account needed
  if (cmd == "ping") return {{"pong", true}, {"version", "0.1.0"}};
  if (cmd == "client.exists") return {{"exists", Client::exists(sarg(a, "dir"), sarg(a, "user"))}};
  if (cmd == "client.create") {
    if (g_client) throw UsageError("an account is already open in this process");
    g_client.emplace(Client::create(sarg(a, "dir"), sarg(a, "user"), sarg(a, "passphrase"), a.value("kdf", "moderate")));
    return {{"bundle", g_client->bundle()}, {"summary", g_client->summary()}};
  }
  if (cmd == "client.open") {
    if (g_client) throw UsageError("an account is already open in this process");
    g_client.emplace(Client::open(sarg(a, "dir"), sarg(a, "user"), sarg(a, "passphrase")));
    return {{"bundle", g_client->bundle()}, {"summary", g_client->summary()}};
  }
  // server side checks, stateless
  if (cmd == "server.verify_bundle") {
    const PublicIdentity p = verify_bundle(arg(a, "bundle"));
    return {{"user", p.user}, {"sig_pk", to_base64(p.sig_pk)}, {"created", p.created}};
  }
  if (cmd == "server.verify_login") {
    const std::string user = sarg(a, "user");
    const bool valid = valid_username(user) &&
                       mldsa_verify(b64arg(a, "sig_pk"), login_transcript(user, b64arg(a, "challenge")), b64arg(a, "sig"));
    return {{"valid", valid}};
  }
  static const std::set<std::string> account_cmds = {
      "bundle", "auth.sign", "summary", "history", "contacts.add_bundle", "contacts.verify", "contacts.accept_change",
      "contacts.safety_number", "contacts.list", "dm.request", "dm.accept", "dm.decline", "dm.send", "receive"};
  if (!account_cmds.count(cmd)) throw UsageError("unknown command: " + cmd);
  Client& c = client();
  if (cmd == "bundle") return {{"bundle", c.bundle()}};
  if (cmd == "auth.sign") return c.sign_login(b64arg(a, "challenge"));
  if (cmd == "summary") return c.summary();
  if (cmd == "history") return {{"conv", sarg(a, "conv")}, {"entries", c.history(sarg(a, "conv"), a.value("limit", 200))}};
  if (cmd == "contacts.add_bundle") return c.add_bundle(arg(a, "bundle"));
  if (cmd == "contacts.verify") return c.verify_contact(sarg(a, "user"));
  if (cmd == "contacts.accept_change") return c.accept_key_change(sarg(a, "user"));
  if (cmd == "contacts.safety_number") return c.safety_number(sarg(a, "user"));
  if (cmd == "contacts.list") return {{"contacts", c.contacts()}};
  if (cmd == "dm.request") {
    std::optional<std::string> text;
    if (a.contains("text") && !a.at("text").is_null()) text = sarg(a, "text");
    return c.dm_request(sarg(a, "to"), text);
  }
  if (cmd == "dm.accept") return c.dm_accept(sarg(a, "peer"));
  if (cmd == "dm.decline") return c.dm_decline(sarg(a, "peer"));
  if (cmd == "dm.send") return c.dm_send(sarg(a, "to"), sarg(a, "text"));
  if (cmd == "receive") return c.receive(arg(a, "envelope"));
  throw UsageError("unknown command: " + cmd);
}

}

int main() {
  try {
    pqs::init();
  } catch (const std::exception& e) {
    std::cerr << "pqs-core: " << e.what() << '\n';
    return 1;
  }

  std::string line;
  while (std::getline(std::cin, line)) {
    if (line.empty()) continue;
    json reply = {{"id", nullptr}};
    try {
      json req;
      try {
        req = json::parse(line);
      } catch (const json::exception& e) {
        throw UsageError(std::string("bad JSON: ") + e.what());
      }
      reply["id"] = req.value("id", json());
      if (!req.contains("cmd") || !req.at("cmd").is_string()) throw UsageError("request needs a string 'cmd'");
      try {
        reply["result"] = handle(req.at("cmd").get<std::string>(), req.value("args", json::object()));
      } catch (const json::exception& e) {
        // wrong typed field in an envelope or vault is bad outside data, so protocol error not usage
        throw ProtocolError(std::string("malformed data: ") + e.what());
      }
      reply["ok"] = true;
    } catch (const UsageError& e) {
      reply["ok"] = false;
      reply["code"] = "usage";
      reply["error"] = e.what();
    } catch (const ProtocolError& e) {
      reply["ok"] = false;
      reply["code"] = "protocol";
      reply["error"] = e.what();
    } catch (const std::exception& e) {
      reply["ok"] = false;
      reply["code"] = "internal";
      reply["error"] = e.what();
    }
    std::cout << reply.dump() << '\n' << std::flush;
  }
  return 0;
}
