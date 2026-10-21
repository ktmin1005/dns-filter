// main.cpp -- multithreaded DNS filtering server.
//
// One receiver thread reads queries from the client socket and places them
// on a bounded queue. A fixed pool of worker threads takes queries off the
// queue and, for each one: parses and validates it, then either answers
// NXDOMAIN (blocked) or forwards it upstream and relays the reply.
//
// Shared state and why it's safe:
//   - WorkQueue: protected by its own mutex.
//   - Blocklist: loaded before any thread starts, then only read (const).
//     Concurrent reads of an unmodified container are safe.
//   - Client socket: sendto() on one UDP socket from several threads is safe;
//     each call sends one complete datagram.
//   - Stats: std::atomic counters.
//   - Each worker has its OWN upstream socket, so replies can never be
//     delivered to the wrong worker.

#include <arpa/inet.h>    // htons, inet_pton, inet_ntop
#include <netinet/in.h>   // sockaddr_in
#include <sys/socket.h>   // socket, bind, connect, send, recv, sendto, recvfrom
#include <sys/time.h>     // timeval
#include <unistd.h>       // close

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>        // memcpy, memset, memcmp
#include <functional>     // std::ref, std::cref
#include <optional>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "blocklist.hpp"
#include "dns_parser.hpp"
#include "work_queue.hpp"

namespace {

constexpr uint16_t kPort = 5300;          // dev port; 53 at deployment
constexpr bool kDebug = false;            // true = hex dumps and parsed fields
constexpr const char* kUpstreamIp = "1.1.1.1";
constexpr int kUpstreamTimeoutSec = 2;
constexpr int kMaxReplyReads = 4;         // bound on stale/bogus replies skipped
constexpr unsigned kWorkers = 4;          // one per Pi 400 core; tune by benchmark
constexpr std::size_t kQueueCapacity = 256;   // max queued queries (~1 MB worst case)

constexpr uint16_t kRcodeServfail = 2;
constexpr uint16_t kRcodeNxdomain = 3;

// Set by the signal handler on Ctrl+C (SIGINT) or SIGTERM. sig_atomic_t is
// the only type the C++ standard guarantees is safe to write from a handler.
volatile std::sig_atomic_t g_stop = 0;

extern "C" void handle_stop_signal(int) { g_stop = 1; }

// One received packet waiting to be handled.
struct Job {
    std::vector<uint8_t> packet;   // exactly the bytes received
    sockaddr_in client{};
    socklen_t client_len = 0;
};

struct Stats {
    std::atomic<uint64_t> received{0};
    std::atomic<uint64_t> dropped{0};     // queue full
    std::atomic<uint64_t> rejected{0};    // failed validation
    std::atomic<uint64_t> blocked{0};
    std::atomic<uint64_t> forwarded{0};
    std::atomic<uint64_t> servfail{0};
};

// Sends a reply containing only the header and question, with the given RCODE.
// parse_query() guarantees q.question_end <= the packet length <= 4096,
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

// Creates a UDP socket connected to the upstream resolver, with a receive
// timeout. Returns -1 (after printing why) on any failure.
int make_upstream_socket() {
    int up = socket(AF_INET, SOCK_DGRAM, 0);
    if (up < 0) { std::perror("upstream socket"); return -1; }

    timeval tv{};
    tv.tv_sec = kUpstreamTimeoutSec;
    if (setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0) {
        std::perror("setsockopt (upstream timeout)"); close(up); return -1;
    }

    sockaddr_in upstream{};
    upstream.sin_family = AF_INET;
    upstream.sin_port = htons(53);
    if (inet_pton(AF_INET, kUpstreamIp, &upstream.sin_addr) != 1) {
        std::fprintf(stderr, "Invalid upstream address: %s\n", kUpstreamIp);
        close(up); return -1;
    }
    // Connected UDP socket: the kernel drops any packet not from upstream:53.
    if (connect(up, reinterpret_cast<sockaddr*>(&upstream), sizeof upstream) < 0) {
        std::perror("connect upstream"); close(up); return -1;
    }
    return up;
}

// Handles one query from start to finish. Runs on a worker thread.
void handle_job(const Job& job, int client_fd, int up,
                const Blocklist& blocklist, Stats& stats) {
    const uint8_t* buf = job.packet.data();
    const std::size_t n = job.packet.size();

    char ip[INET_ADDRSTRLEN] = "?";
    if (inet_ntop(AF_INET, &job.client.sin_addr, ip, sizeof ip) == nullptr) {
        std::strcpy(ip, "?");
    }
    if (kDebug) {
        std::printf("Received %zu bytes from %s:%u\n", n, ip, ntohs(job.client.sin_port));
        hex_dump(buf, n);
    }

    DnsQuery q;
    ParseError err = parse_query(buf, n, q);
    if (err != ParseError::None) {
        ++stats.rejected;
        std::printf("REJECTED packet from %s: %s\n", ip, parse_error_text(err));
        return;
    }
    if (kDebug) {
        std::printf("ID=%u RD=%d Name=%s QTYPE=%u\n", static_cast<unsigned>(q.id),
                    (q.flags & 0x0100) ? 1 : 0, q.name.c_str(),
                    static_cast<unsigned>(q.qtype));
    }

    // ---- Blocked: answer NXDOMAIN ourselves ---------------------------------
    if (blocklist.is_blocked(q.name)) {
        send_error(client_fd, buf, q, kRcodeNxdomain, job.client, job.client_len);
        ++stats.blocked;
        std::printf("BLOCKED %s\n", q.name.c_str());
        return;
    }

    // ---- Allowed: forward upstream and relay the reply ----------------------
    if (send(up, buf, n, 0) != static_cast<ssize_t>(n)) {
        ++stats.servfail;
        std::printf("Upstream send failed for %s -> SERVFAIL\n", q.name.c_str());
        send_error(client_fd, buf, q, kRcodeServfail, job.client, job.client_len);
        return;
    }

    uint8_t reply[4096];
    ssize_t m = -1;
    for (int attempt = 0; attempt < kMaxReplyReads; ++attempt) {
        ssize_t r = recv(up, reply, sizeof reply, 0);
        if (r < 0) break;                                       // timeout or error
        bool match = static_cast<std::size_t>(r) >= q.question_end     // checked first
                  && reply[0] == buf[0] && reply[1] == buf[1]         // same ID
                  && (reply[2] & 0x80)                                // QR=1
                  && std::memcmp(reply + 12, buf + 12, q.question_end - 12) == 0;
        if (match) { m = r; break; }                            // stale/bogus: keep waiting
    }
    if (m < 0) {
        ++stats.servfail;
        std::printf("Upstream failed for %s -> SERVFAIL\n", q.name.c_str());
        send_error(client_fd, buf, q, kRcodeServfail, job.client, job.client_len);
        return;
    }
    if (sendto(client_fd, reply, static_cast<std::size_t>(m), 0,
               reinterpret_cast<const sockaddr*>(&job.client), job.client_len) < 0) {
        std::perror("sendto (forwarded reply)");
        return;
    }
    ++stats.forwarded;
    std::printf("FORWARDED %s\n", q.name.c_str());
}

// A worker thread: take jobs until the queue is closed and empty.
void worker_loop(WorkQueue<Job>& queue, int client_fd, int up,
                 const Blocklist& blocklist, Stats& stats) {
    while (std::optional<Job> job = queue.pop()) {
        handle_job(*job, client_fd, up, blocklist, stats);
    }
}

void close_all(int client_fd, const std::vector<int>& upstreams) {
    for (int up : upstreams) close(up);
    if (client_fd >= 0) close(client_fd);
}

}  // namespace

int main(int argc, char* argv[]) {
    // ---- Arguments ----------------------------------------------------------
    if (argc > 2) {
        std::fprintf(stderr, "Usage: %s [blocklist-file]\n", argv[0]);
        return 1;
    }
    const char* list_path = (argc == 2) ? argv[1] : "blocklist.txt";

    // ---- Blocklist: loaded before any thread exists, never modified after ----
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

    // ---- Signals: Ctrl+C / SIGTERM request a clean shutdown ------------------
    // No SA_RESTART, so a blocked recvfrom() returns early with EINTR.
    struct sigaction sa{};
    sa.sa_handler = handle_stop_signal;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, nullptr) < 0 || sigaction(SIGTERM, &sa, nullptr) < 0) {
        std::perror("sigaction");
        return 1;
    }

    // ---- Client-facing socket -------------------------------------------------
    int client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (client_fd < 0) { std::perror("socket"); return 1; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   // only the Pi itself can reach it
    if (bind(client_fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0) {
        std::perror("bind"); close(client_fd); return 1;
    }
    // A 1-second receive timeout so the receiver re-checks g_stop regularly,
    // even if the signal arrives on a different thread.
    timeval rtv{};
    rtv.tv_sec = 1;
    if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof rtv) < 0) {
        std::perror("setsockopt (client timeout)"); close(client_fd); return 1;
    }

    // ---- One upstream socket per worker ----------------------------------------
    std::vector<int> upstreams;
    for (unsigned i = 0; i < kWorkers; ++i) {
        int up = make_upstream_socket();
        if (up < 0) { close_all(client_fd, upstreams); return 1; }
        upstreams.push_back(up);
    }

    // ---- Start workers -----------------------------------------------------------
    WorkQueue<Job> queue(kQueueCapacity);
    Stats stats;
    std::vector<std::thread> workers;
    try {
        for (unsigned i = 0; i < kWorkers; ++i) {
            workers.emplace_back(worker_loop, std::ref(queue), client_fd, upstreams[i],
                                 std::cref(blocklist), std::ref(stats));
        }
    } catch (const std::system_error& e) {
        std::fprintf(stderr, "Failed to start worker thread: %s\n", e.what());
        queue.close();
        for (std::thread& t : workers) t.join();
        close_all(client_fd, upstreams);
        return 1;
    }

    std::printf("Listening on 127.0.0.1:%u with %u workers, forwarding to %s\n",
                kPort, kWorkers, kUpstreamIp);

    // ---- Receiver loop (this thread) -------------------------------------------
    uint8_t buf[4096];
    while (!g_stop) {
        Job job;
        job.client_len = sizeof job.client;
        ssize_t n = recvfrom(client_fd, buf, sizeof buf, 0,
                             reinterpret_cast<sockaddr*>(&job.client), &job.client_len);
        if (n < 0) {
            // Timeout or signal: not an error, just a chance to check g_stop.
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            std::perror("recvfrom");
            continue;
        }
        ++stats.received;
        job.packet.assign(buf, buf + n);
        if (!queue.try_push(std::move(job))) {
            // Queue full: drop rather than reply, so a flood can't turn this
            // server into a source of extra traffic.
            ++stats.dropped;
        }
    }

    // ---- Clean shutdown ------------------------------------------------------------
    std::printf("\nShutting down: finishing queued queries...\n");
    queue.close();                       // workers drain the queue, then exit
    for (std::thread& t : workers) t.join();
    close_all(client_fd, upstreams);

    std::printf("Stats: received=%llu dropped=%llu rejected=%llu blocked=%llu "
                "forwarded=%llu servfail=%llu\n",
                static_cast<unsigned long long>(stats.received.load()),
                static_cast<unsigned long long>(stats.dropped.load()),
                static_cast<unsigned long long>(stats.rejected.load()),
                static_cast<unsigned long long>(stats.blocked.load()),
                static_cast<unsigned long long>(stats.forwarded.load()),
                static_cast<unsigned long long>(stats.servfail.load()));
    return 0;
}
