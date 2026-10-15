// main.cpp -- Stage 0: receive ONE DNS query over UDP and print its raw bytes.
//
// Goal of this program: see exactly what a DNS query looks like on the wire
// before writing any parser. It does not reply, so `dig` will time out.
// That's expected.

#include <arpa/inet.h>    // htons, htonl, ntohs, inet_ntop
#include <netinet/in.h>   // sockaddr_in, INADDR_LOOPBACK
#include <sys/socket.h>   // socket, bind, recvfrom
#include <unistd.h>       // close
#include <string>
#include <cctype>
#include <cstring>

#include <cstdint>        // uint8_t, uint16_t
#include <cstdio>         // printf, perror
#include <sys/time.h>
#include "blocklist.hpp"

static void send_error(int fd, const uint8_t* query, ssize_t question_end, uint16_t query_flags, uint16_t rcode, const sockaddr_in& client, socklen_t client_len) {
    uint8_t resp[4096];
    std::memcpy(resp, query, question_end);
    uint16_t f = 0x8000 | (query_flags & 0x0100) | 0x0080 | rcode;
    resp[2] = f >> 8;
    resp[3] = f & 0xFF;
    std::memset(&resp[6], 0, 6);
    if (sendto(fd, resp, question_end, 0, reinterpret_cast<const sockaddr*>(&client), client_len) < 0) {
        std::perror("sendto (error reply)");
    }
}

int main() {
    // Port 5300 for development: ports below 1024 (like DNS's real port 53)
    // need root, and 5353 is already used by avahi (mDNS).
    constexpr uint16_t kPort = 5300;

    // 1. Create a socket.
    //    AF_INET    = IPv4
    //    SOCK_DGRAM = UDP (DNS queries normally travel over UDP)
    //    The return value is a file descriptor: just an integer handle the
    //    kernel gives you, like a ticket number for this socket.
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        std::perror("socket");   // prints the OS's reason for the failure
        return 1;
    }

    // 2. Describe the address we want to listen on.
    //    `{}` zero-initializes every field, so no garbage values.
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    // htons/htonl = "host to network short/long". Network protocols use
    // big-endian byte order; the Pi's CPU is little-endian, so the bytes of
    // multi-byte numbers must be swapped before going into these fields.
    addr.sin_port = htons(kPort);
    // INADDR_LOOPBACK = 127.0.0.1: only programs on the Pi itself can reach
    // this server. Safe while experimenting. Later you'll switch this to
    // INADDR_ANY so other devices on your network can use it.
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    // 3. Bind: claim that address and port for this socket.
    //    The cast is needed because the C socket API takes a generic
    //    `sockaddr*` that can point to IPv4, IPv6, or other address types.
    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0) {
        std::perror("bind");     // e.g. "Address already in use"
        close(fd);
        return 1;
    }
    std::printf("Listening on 127.0.0.1:%u ... run dig in another terminal\n", kPort);

    // 4. Wait for one packet. recvfrom() blocks (sleeps) until data arrives.
    //    buf    = where the packet's bytes are copied
    //    client = filled in with the sender's address (who to reply to later)
    //    n      = how many bytes actually arrived. ALWAYS trust n, never
    //             sizeof(buf): only the first n bytes are real data.
    int up = socket(AF_INET, SOCK_DGRAM, 0);
    if (up < 0) { std::perror("upstream socket"); close(fd); return 1; }

    timeval tv{};
    tv.tv_sec = 2;
    if (setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0) {
        std::perror("setsockopt"); close(up); close(fd); return 1;
    }

    sockaddr_in upstream{};
    upstream.sin_family = AF_INET;
    upstream.sin_port = htons(53);
    if (inet_pton(AF_INET, "1.1.1.1", &upstream.sin_addr) != 1) {
        std::fprintf(stderr, "Invalid upstream address\n"); close(up); close(fd); return 1;
    }
    if (connect(up, reinterpret_cast<sockaddr*>(&upstream), sizeof upstream) < 0) {
        std::perror("connect upstream"); close(up); close(fd); return 1;
    }
    Blocklist blocklist;
    if (!blocklist.load("blocklist.txt")) {
        std::fprintf(stderr, "Cannot open blocklist.txt\n");
        close(up); close(fd); return 1;
    }
    std::printf("Loaded %zu blocked domains (%zu invalid lines skipped)\n",
                blocklist.size(), blocklist.skipped());
    if (blocklist.hit_limit()) std::fprintf(stderr, "Warning: blocklist truncated at entry limit\n");
    uint8_t buf[4096];           // big enough for EDNS0-sized packets
    while (true) {
        sockaddr_in client{};
        socklen_t client_len = sizeof client;
        ssize_t n = recvfrom(fd, buf, sizeof buf, 0,
                             reinterpret_cast<sockaddr*>(&client), &client_len);
        if (n < 0) {
            std::perror("recvfrom");
            continue;
        }

    // 5. Print who sent it. inet_ntop turns the binary IP into text.
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client.sin_addr, ip, sizeof ip);
        std::printf("Received %zd bytes from %s:%u\n\n", n, ip, ntohs(client.sin_port));

    // 6. Hex dump: each byte as two hex digits, 16 bytes per row.
    //    The left column is the offset (position) of the row's first byte,
    //    which makes it easy to say "the header is bytes 0-11".
        for (ssize_t i = 0; i < n; ++i) {
            if (i % 16 == 0) std::printf("%04zx:  ", static_cast<size_t>(i));
            std::printf("%02x ", buf[i]);
            if ((i + 1) % 16 == 0) std::printf("\n");
        }
        std::printf("\n");

        if (n < 12) {                                                // a DNS header is 12 bytes
            std::printf("Too short for a DNS header, skilling/n/n");
            continue;
        }
        uint16_t id    = (buf[0] << 8) | buf[1];                     // bytes 0-1: transaction ID
        uint16_t flags = (buf[2] << 8) | buf[3];                      // bytes 2-3: flags
        bool rd = (flags & 0x0100) != 0;                             // RD = "recursion desired"
        if (flags & 0x8000) {
            std::printf("Not a query (QR=1), ignoring\n\n");
            continue;
        }
        uint16_t opcode = (flags >> 11) & 0xF;
        if (opcode != 0) {
            std::printf("Unsupported opcode %u, ignoring\n\n", static_cast<unsigned>(opcode));
            continue;
        }
        uint16_t qdcount = (buf[4] << 8) | buf[5];
        if (qdcount != 1) {
            std::printf("Expected 1 question, got %u, ignoring\n\n", static_cast<unsigned>(qdcount));
            continue;
        }
        std::printf("ID=%u RD=%d\n\n", static_cast<unsigned>(id), rd ? 1 : 0);

        std::string name;          // the domain name we're building, e.g. "example.com"
        ssize_t pos = 12;          // the question section starts right after the 12-byte header
        bool ok = false;           // becomes true only if we reach the 00 terminator safely
        while (pos < n) {
            uint8_t len = buf[pos];                          // the length byte
            if (len == 0) { ok = true; ++pos; break; }       // end of name
            if (len > 63 || pos + 1 + len > n) break;        // label too long, or runs past the packet
            if (!name.empty()) name += '.';                  // dot between labels
            for (int i = 0; i < len; i++) {
                name.push_back(static_cast<char>(std::tolower(buf[pos + 1 + i])));
            }
            pos += 1 + len;                                  // jump to the next length byte
        }
        if (!ok || name.size() > 253) {
            std::printf("Malformed name, skipping\n\n");
            continue;
        }
        std::printf("Name=%s\n\n", name.c_str());

        if (pos + 4 > n) {
            std::printf("Truncated question for %s (no QTYPE/QCLASS), skipping \n\n", name.c_str());
            continue;
        }
        uint16_t qtype = (buf[pos] << 8)| buf[pos + 1];
        std::printf("Qtype=%u\n\n", static_cast<unsigned>(qtype));
        ssize_t question_end = pos + 4;                      // name + QTYPE (2) + QCLASS (2)

        if (blocklist.is_blocked(name)) {
            send_error(fd, buf, question_end, flags, 3, client, client_len);
            std::printf("BLOCKED %s -> NXDOMAIN\n\n", name.c_str());
        }
        else {
            if (send(up, buf, n, 0) != n) {
                std::printf("Upstream send failed for %s -> SERVFAIL\n\n", name.c_str());
                send_error(fd, buf, question_end, flags, 2, client, client_len);
                continue;
            }
            uint8_t reply[4098];
            ssize_t m = -1;

            for (int attempt = 0; attempt < 4; ++attempt) {  // skip at most a few stale replies
                ssize_t r = recv(up, reply, sizeof reply, 0);
                if (r < 0) break;                            // timeout or error: give up
                bool match = r >= question_end
                          && reply[0] == buf[0] && reply[1] == buf[1]     // same ID
                          && (reply[2] & 0x80)                            // QR=1: a response
                          && std::memcmp(reply + 12, buf + 12, question_end - 12) == 0;
                if (match) { m = r; break; }                 // the real answer
            }
            if (m < 0) {
                std::printf("Upstream failed for %s -> SERVFAIL\n\n", name.c_str());
                send_error(fd, buf, question_end, flags, 2, client, client_len);
                continue;
            }
            if (sendto(fd, reply, m, 0, reinterpret_cast<sockaddr*>(&client), client_len) < 0) {
                std::perror("sendto (forwarded reply)");
                continue;
            }
            std::printf("FORWARDED %s (%zd-byte reply)\n\n", name.c_str(), m);
        }
    }

    // 7. Release the socket. (The OS would do this on exit anyway, but
    //    cleaning up explicitly is a good habit for the long-running server.)
    close(up);
    close(fd);
    return 0;
}
