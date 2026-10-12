// main.cpp -- Stage 0: receive ONE DNS query over UDP and print its raw bytes.
//
// Goal of this program: see exactly what a DNS query looks like on the wire
// before writing any parser. It does not reply, so `dig` will time out.
// That's expected.

#include <arpa/inet.h>    // htons, htonl, ntohs, inet_ntop
#include <netinet/in.h>   // sockaddr_in, INADDR_LOOPBACK
#include <sys/socket.h>   // socket, bind, recvfrom
#include <unistd.h>       // close

#include <cstdint>        // uint8_t, uint16_t
#include <cstdio>         // printf, perror

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
        std::printf("ID=%u RD=%d\n\n", static_cast<unsigned>(id), rd ? 1 : 0);
    }

    // 7. Release the socket. (The OS would do this on exit anyway, but
    //    cleaning up explicitly is a good habit for the long-running server.)
    close(fd);
    return 0;
}
