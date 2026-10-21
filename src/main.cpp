// main.cpp -- DNS filtering server.
//
// For each UDP query: parse and validate it, then either answer NXDOMAIN
// (blocked) or forward it to the upstream resolver and relay the reply.

#include <arpa/inet.h>    // htons, inet_pton, inet_ntop
#include <netinet/in.h>   // sockaddr_in
#include <sys/socket.h>   // socket, bind, connect, send, recv, sendto, recvfrom
#include <sys/time.h>     // timeval
#include <unistd.h>       // close

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>        // memcpy, memset, memcmp

#include "blocklist.hpp"
#include "dns_parser.hpp"

namespace {

constexpr uint16_t kPort = 5300;          // dev port; 53 at deployment
constexpr bool kDebug = false;            // true = hex dumps and parsed fields
constexpr const char* kUpstreamIp = "1.1.1.1";
constexpr int kUpstreamTimeoutSec = 2;
constexpr int kMaxReplyReads = 4;         // bound on stale/bogus replies skipped

constexpr uint16_t kRcodeServfail = 2;
constexpr uint16_t kRcodeNxdomain = 3;

// Sends a reply containing only the header and question, with the given RCODE.
// parse_query() guarantees q.question_end <= the received length <= 4096,
// so the copy can't overflow `resp`.
void send_error(int fd, const uint8_t* query, const DnsQuery& q, uint16_t rcode,
                const sockaddr_in& client, socklen_t client_len) {
    uint8_t resp[4096];
    std::memcpy(resp, query, q.question_end);
    // QR=1, copy RD, RA=1, RCODE. Opcode 0, AA/TC/AD all 0.
    uint16_t f = 0x8000 | (q.flags & 0x0100) | 0x0080 | rcode;
    resp[2] = static_cast<uint8_t>(f >> 8);
    resp[3] = static_cast<uint8_t>(f & 0xFF);
    std::memset(&resp[6], 0, 6);            // ANCOUNT, NSCOUNT, ARCOUNT = 0
    if (sendto(fd, resp, q.question_end, 0,
               reinterpret_cast<const sockaddr*>(&client), client_len) < 0) {
        std::perror("sendto (error reply)");
    }
}

void hex_dump(const uint8_t* data, std::size_t len) {
    for (std::size_t i = 0; i < len; ++i) {
        if (i % 16 == 0) std::printf("%04zx:  ", i);
        std::printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) std::printf("\n");
    }
    std::printf("\n");
}

}  // namespace

int main(int argc, char* argv[]) {
    // ---- Arguments -------------------------------------------------------
    if (argc > 2) {
        std::fprintf(stderr, "Usage: %s [blocklist-file]\n", argv[0]);
        return 1;
    }
    const char* list_path = (argc == 2) ? argv[1] : "blocklist.txt";

    // ---- Blocklist (loaded first: nothing to clean up if it fails) ---------
    Blocklist blocklist;
    if (!blocklist.load(list_path)) {
        std::fprintf(stderr, "Cannot open blocklist: %s\n", list_path);
        return 1;
    }
    std::printf("Loaded %zu blocked domains (%zu invalid lines skipped)\n",
                blocklist.size(), blocklist.skipped());
    if (blocklist.hit_limit()) {
        std::fprintf(stderr, "Warning: blocklist truncated at entry limit\n");
    }

    // ---- Client-facing socket ----------------------------------------------
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { std::perror("socket"); return 1; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   // only the Pi itself can reach it
    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0) {
        std::perror("bind"); close(fd); return 1;
    }

    // ---- Upstream socket ----------------------------------------------------
    int up = socket(AF_INET, SOCK_DGRAM, 0);
    if (up < 0) { std::perror("upstream socket"); close(fd); return 1; }

    timeval tv{};
    tv.tv_sec = kUpstreamTimeoutSec;
    if (setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0) {
        std::perror("setsockopt"); close(up); close(fd); return 1;
    }

    sockaddr_in upstream{};
    upstream.sin_family = AF_INET;
    upstream.sin_port = htons(53);
    if (inet_pton(AF_INET, kUpstreamIp, &upstream.sin_addr) != 1) {
        std::fprintf(stderr, "Invalid upstream address: %s\n", kUpstreamIp);
        close(up); close(fd); return 1;
    }
    // A connected UDP socket: the kernel drops any packet not from upstream:53.
    if (connect(up, reinterpret_cast<sockaddr*>(&upstream), sizeof upstream) < 0) {
        std::perror("connect upstream"); close(up); close(fd); return 1;
    }

    std::printf("Listening on 127.0.0.1:%u, forwarding to %s\n", kPort, kUpstreamIp);

    // ---- Main loop ----------------------------------------------------------
    uint8_t buf[4096];
    while (true) {
        sockaddr_in client{};
        socklen_t client_len = sizeof client;
        ssize_t n = recvfrom(fd, buf, sizeof buf, 0,
                             reinterpret_cast<sockaddr*>(&client), &client_len);
        if (n < 0) { std::perror("recvfrom"); continue; }

        char ip[INET_ADDRSTRLEN] = "?";
        inet_ntop(AF_INET, &client.sin_addr, ip, sizeof ip);
        if (kDebug) {
            std::printf("Received %zd bytes from %s:%u\n", n, ip, ntohs(client.sin_port));
            hex_dump(buf, static_cast<std::size_t>(n));
        }

        DnsQuery q;
        ParseError err = parse_query(buf, static_cast<std::size_t>(n), q);
        if (err != ParseError::None) {
            std::printf("REJECTED packet from %s: %s\n", ip, parse_error_text(err));
            continue;
        }
        if (kDebug) {
            std::printf("ID=%u RD=%d Name=%s QTYPE=%u\n", static_cast<unsigned>(q.id),
                        (q.flags & 0x0100) ? 1 : 0, q.name.c_str(),
                        static_cast<unsigned>(q.qtype));
        }

        // ---- Blocked: answer NXDOMAIN ourselves ------------------------------
        if (blocklist.is_blocked(q.name)) {
            send_error(fd, buf, q, kRcodeNxdomain, client, client_len);
            std::printf("BLOCKED %s\n", q.name.c_str());
            continue;
        }

        // ---- Allowed: forward upstream and relay the reply -------------------
        if (send(up, buf, static_cast<std::size_t>(n), 0) != n) {
            std::printf("Upstream send failed for %s -> SERVFAIL\n", q.name.c_str());
            send_error(fd, buf, q, kRcodeServfail, client, client_len);
            continue;
        }

        uint8_t reply[4096];
        ssize_t m = -1;
        for (int attempt = 0; attempt < kMaxReplyReads; ++attempt) {
            ssize_t r = recv(up, reply, sizeof reply, 0);
            if (r < 0) break;                                   // timeout or error
            bool match = static_cast<std::size_t>(r) >= q.question_end   // checked first
                      && reply[0] == buf[0] && reply[1] == buf[1]       // same ID
                      && (reply[2] & 0x80)                              // QR=1
                      && std::memcmp(reply + 12, buf + 12, q.question_end - 12) == 0;
            if (match) { m = r; break; }                        // stale/bogus: keep waiting
        }
        if (m < 0) {
            std::printf("Upstream failed for %s -> SERVFAIL\n", q.name.c_str());
            send_error(fd, buf, q, kRcodeServfail, client, client_len);
            continue;
        }
        if (sendto(fd, reply, static_cast<std::size_t>(m), 0,
                   reinterpret_cast<sockaddr*>(&client), client_len) < 0) {
            std::perror("sendto (forwarded reply)");
            continue;
        }
        std::printf("FORWARDED %s\n", q.name.c_str());
    }

    close(up);
    close(fd);
    return 0;
}
