// dot_probe.cpp -- checks DNS over TLS from this machine, outside the server.
//
//   ./dot_probe              query example.com over TLS to 1.1.1.1
//
// Runs two tests:
//   1. The real certificate name (cloudflare-dns.com): must succeed.
//   2. A WRONG name: must FAIL. If it succeeds, certificate checking is
//      broken and the encryption would protect nothing.

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <csignal>

#include "dot_client.hpp"

namespace {

// A fixed query for example.com, type A, class IN, with RD set.
const uint8_t kQuery[] = {
    0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
    0x00, 0x01, 0x00, 0x01,
};

bool run(const DotContext& ctx, const char* tls_name) {
    DotConnection conn(ctx, "1.1.1.1", tls_name, 3);
    uint8_t resp[4096];
    ssize_t n = conn.exchange(kQuery, sizeof kQuery, resp, sizeof resp);
    if (n < 12) {
        std::printf("  [%s] no valid response\n", tls_name);
        return false;
    }
    unsigned rcode = resp[3] & 0x0F;
    unsigned answers = (static_cast<unsigned>(resp[6]) << 8) | resp[7];
    bool id_ok = resp[0] == kQuery[0] && resp[1] == kQuery[1];
    std::printf("  [%s] %zd-byte response, id_match=%s, rcode=%u, answers=%u\n",
                tls_name, n, id_ok ? "yes" : "NO", rcode, answers);
    return id_ok && rcode == 0 && answers > 0;
}

}  // namespace

int main() {
    std::signal(SIGPIPE, SIG_IGN);   // a closed TLS socket must not kill us
    DotContext ctx;
    if (!ctx.ok()) { std::fprintf(stderr, "Could not create TLS context\n"); return 1; }

    std::printf("Test 1: correct certificate name (should succeed)\n");
    bool good = run(ctx, "cloudflare-dns.com");

    std::printf("Test 2: wrong certificate name (should FAIL)\n");
    bool bad = run(ctx, "wrong-name.invalid");

    std::printf("\n%s\n", (good && !bad) ? "PASS: DoT works and certificates are verified."
                                        : "FAIL: see above.");
    return (good && !bad) ? 0 : 1;
}
