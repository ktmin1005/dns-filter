// main.cpp -- multithreaded DNS filtering server (deployed as a systemd service).
//
// One receiver thread reads queries from the client socket and places them
// on a bounded queue. A fixed pool of worker threads takes queries off the
// queue and, for each one: parses and validates it, then either answers
// NXDOMAIN (blocked) or forwards it upstream and relays the reply.
//
// Shared state and why it's safe:
//   - Allow-list and RateLimiter: used only by the receiver thread.
//   - WorkQueue: protected by its own mutex.
//   - Blocklist: loaded before any thread starts, then only read (const).
//     Concurrent reads of an unmodified container are safe.
//   - Client socket: sendto() on one UDP socket from several threads is safe;
//     each call sends one complete datagram.
//   - Stats: std::atomic counters.
//   - Upstream sockets: each query gets a brand-new socket (fresh random
//     source port) and a fresh random query ID, so replies can never reach
//     the wrong worker and off-path spoofing must guess both. See
//     forward_upstream().
//   - Stop flag: a lock-free std::atomic<bool>, safe to set from a signal
//     handler and read from another thread.

#include <arpa/inet.h>    // htons, inet_pton, inet_ntop
#include <netinet/in.h>   // sockaddr_in
#include <pthread.h>      // pthread_sigmask
#include <signal.h>       // sigset_t, sigaction
#include <sys/random.h>   // getrandom
#include <sys/socket.h>   // socket, bind, connect, send, recv, sendto, recvfrom
#include <sys/time.h>     // timeval
#include <unistd.h>       // close

#include <atomic>
#include <chrono>
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

#include "access_control.hpp"
#include "blocklist.hpp"
#include "dns_parser.hpp"
#include "work_queue.hpp"

namespace {

// Where the server listens. Binding to the Pi's specific LAN address (not
// 0.0.0.0) means it can't be reached through any other interface, such as a
// VPN or a second network adapter. Requires a DHCP reservation for this IP.
constexpr const char* kBindIp = "10.0.0.131";
constexpr uint16_t kPort = 53;            // standard DNS port
constexpr bool kDebug = false;            // true = hex dumps and parsed fields
// Per-query log lines (BLOCKED/FORWARDED) record which domains each device
// looks up -- other people's browsing, once they use this server. Off by
// default; periodic counters are logged instead.
constexpr bool kLogQueries = false;
constexpr int kStatsIntervalSec = 300;    // log counters every 5 minutes
constexpr const char* kUpstreamIp = "1.1.1.1";
constexpr int kUpstreamTimeoutSec = 2;
constexpr int kMaxReplyReads = 4;         // bound on stale/bogus replies skipped
constexpr unsigned kWorkers = 4;          // one per Pi 400 core; tune by benchmark
constexpr std::size_t kQueueCapacity = 256;   // max queued queries (~1 MB worst case)

// Only these subnets may use the server. Everything else is dropped silently.
// This MUST match your home network -- check with: ip -4 addr show
// (Loopback isn't listed: the server only listens on the LAN address, and
// the Pi's own queries to that address come from 10.0.0.131, which is inside.)
constexpr const char* kAllowedNets[] = {"10.0.0.0/24"};

// Per-client rate limit: up to 1000 queries per minute (a burst of 1000,
// refilled at 1000/60 per second). Measured on real browsing: a burst limit
// of 100 throttled normal use -- a busy page plus background apps can issue
// hundreds of lookups in seconds, and every dropped query triggers a client
// retry, which makes the burst bigger. 1000/minute matches the default used
// by Pi-hole and still stops a single device from flooding the server.
constexpr double kRatePerSec = 1000.0 / 60.0;
constexpr double kBurst = 1000.0;
constexpr std::size_t kMaxTrackedClients = 1024;

constexpr uint16_t kRcodeServfail = 2;
constexpr uint16_t kRcodeNxdomain = 3;

// How long clients may cache a "blocked" answer. Longer means fewer repeat
// queries for the same tracker; shorter means allowlist changes reach clients
// sooner. 60 seconds balances the two.
constexpr uint32_t kBlockedTtl = 60;

// A synthetic SOA record, appended to the authority section of every block
// reply. RFC 2308: a resolver may cache a "no such domain" answer only if it
// carries a SOA record, for min(record TTL, SOA MINIMUM). Without one, apps
// re-ask for blocked domains over and over.
// The names use ".invalid", a top-level domain reserved so it can never exist.
constexpr uint8_t kBlockedSoa[] = {
    0xC0, 0x0C,                         // owner: pointer to the question name (offset 12)
    0x00, 0x06,                         // TYPE  = SOA
    0x00, 0x01,                         // CLASS = IN
    0x00, 0x00, 0x00, kBlockedTtl,      // TTL (fits in one byte: 60 < 256)
    0x00, 67,                           // RDLENGTH: 18 + 29 + 20 bytes below
    // MNAME: sinkhole.invalid.  (18 bytes)
    8, 's','i','n','k','h','o','l','e', 7, 'i','n','v','a','l','i','d', 0,
    // RNAME: hostmaster.sinkhole.invalid.  (29 bytes)
    10, 'h','o','s','t','m','a','s','t','e','r',
    8, 's','i','n','k','h','o','l','e', 7, 'i','n','v','a','l','i','d', 0,
    // SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM  (5 x 4 bytes)
    0x00, 0x00, 0x00, 0x01,             // SERIAL  = 1
    0x00, 0x00, 0x0E, 0x10,             // REFRESH = 3600
    0x00, 0x00, 0x02, 0x58,             // RETRY   = 600
    0x00, 0x01, 0x51, 0x80,             // EXPIRE  = 86400
    0x00, 0x00, 0x00, kBlockedTtl,      // MINIMUM = negative-cache lifetime
};
static_assert(kBlockedTtl < 256, "TTL is encoded in a single byte above");
static_assert(sizeof(kBlockedSoa) == 12 + 67, "SOA record length must match RDLENGTH");

// Set by the signal handler on Ctrl+C (SIGINT) or SIGTERM, read by the
// receiver thread. A lock-free atomic is both async-signal-safe and safe to
// share between threads; `volatile sig_atomic_t` is only guaranteed for a
// handler and code on the SAME thread, so it would be a data race here.
std::atomic<bool> g_stop{false};
static_assert(std::atomic<bool>::is_always_lock_free,
              "the stop flag must be lock-free to be set from a signal handler");

extern "C" void handle_stop_signal(int) { g_stop.store(true); }

// One received packet waiting to be handled.
struct Job {
    std::vector<uint8_t> packet;   // exactly the bytes received
    sockaddr_in client{};
    socklen_t client_len = 0;
};

struct Stats {
    std::atomic<uint64_t> received{0};
    std::atomic<uint64_t> denied{0};      // source not in an allowed subnet
    std::atomic<uint64_t> rate_limited{0};
    std::atomic<uint64_t> dropped{0};     // queue full
    std::atomic<uint64_t> rejected{0};    // failed validation
    std::atomic<uint64_t> blocked{0};
    std::atomic<uint64_t> forwarded{0};
    std::atomic<uint64_t> servfail{0};
};

// Sends a reply containing the header and question with the given RCODE and,
// for blocked names, the synthetic SOA record so clients can cache the block.
// parse_query() guarantees q.question_end <= the packet length <= 4096, and
// limits names to 253 characters, so question_end is at most a few hundred
// bytes; the explicit size check below enforces the bound anyway.
void send_error(int fd, const uint8_t* query, const DnsQuery& q, uint16_t rcode,
                bool with_soa, const sockaddr_in& client, socklen_t client_len) {
    uint8_t resp[4096];
    std::memcpy(resp, query, q.question_end);
    // QR=1, copy RD, RA=1, RCODE. Opcode 0, AA/TC/AD all 0.
    uint16_t f = 0x8000 | (q.flags & 0x0100) | 0x0080 | rcode;
    resp[2] = static_cast<uint8_t>(f >> 8);
    resp[3] = static_cast<uint8_t>(f & 0xFF);
    std::memset(&resp[6], 0, 6);            // ANCOUNT, NSCOUNT, ARCOUNT = 0

    std::size_t len = q.question_end;
    if (with_soa && len + sizeof kBlockedSoa <= sizeof resp) {
        std::memcpy(resp + len, kBlockedSoa, sizeof kBlockedSoa);
        len += sizeof kBlockedSoa;
        resp[9] = 1;                        // NSCOUNT = 1 (low byte; high byte is 0)
    }
    if (sendto(fd, resp, len, 0,
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

// Closes a file descriptor when it goes out of scope, on every return path.
struct FdGuard {
    int fd;
    explicit FdGuard(int f) : fd(f) {}
    ~FdGuard() { if (fd >= 0) close(fd); }
    FdGuard(const FdGuard&) = delete;
    FdGuard& operator=(const FdGuard&) = delete;
};

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
void handle_job(const Job& job, int client_fd,
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
        send_error(client_fd, buf, q, kRcodeNxdomain, true, job.client, job.client_len);
        ++stats.blocked;
        if (kLogQueries) std::printf("BLOCKED %s\n", q.name.c_str());
        return;
    }

    // ---- Allowed: forward upstream and relay the reply ----------------------
    // Spoofing defense (the Kaminsky attack): an off-path attacker forging a
    // reply from 1.1.1.1 must guess the query ID AND our source port. So each
    // query gets a fresh socket -- a new random port from the kernel -- and a
    // fresh random ID from the OS's secure random generator, instead of
    // trusting whatever ID the client chose.
    FdGuard up(make_upstream_socket());
    uint16_t upstream_id = 0;
    if (up.fd < 0 || getrandom(&upstream_id, sizeof upstream_id, 0) != sizeof upstream_id) {
        ++stats.servfail;
        std::printf("Upstream setup failed for %s -> SERVFAIL\n", q.name.c_str());
        send_error(client_fd, buf, q, kRcodeServfail, false, job.client, job.client_len);
        return;
    }

    std::vector<uint8_t> out(buf, buf + n);              // forwarded copy
    out[0] = static_cast<uint8_t>(upstream_id >> 8);
    out[1] = static_cast<uint8_t>(upstream_id & 0xFF);
    if (send(up.fd, out.data(), out.size(), 0) != static_cast<ssize_t>(out.size())) {
        ++stats.servfail;
        std::printf("Upstream send failed for %s -> SERVFAIL\n", q.name.c_str());
        send_error(client_fd, buf, q, kRcodeServfail, false, job.client, job.client_len);
        return;
    }

    uint8_t reply[4096];
    ssize_t m = -1;
    for (int attempt = 0; attempt < kMaxReplyReads; ++attempt) {
        ssize_t r = recv(up.fd, reply, sizeof reply, 0);
        if (r < 0) break;                                       // timeout or error
        bool match = static_cast<std::size_t>(r) >= q.question_end     // checked first
                  && reply[0] == out[0] && reply[1] == out[1]         // our random ID
                  && (reply[2] & 0x80)                                // QR=1
                  && std::memcmp(reply + 12, buf + 12, q.question_end - 12) == 0;
        if (match) { m = r; break; }                            // stale/bogus: keep waiting
    }
    if (m < 0) {
        ++stats.servfail;
        std::printf("Upstream failed for %s -> SERVFAIL\n", q.name.c_str());
        send_error(client_fd, buf, q, kRcodeServfail, false, job.client, job.client_len);
        return;
    }
    reply[0] = buf[0];                                          // restore the
    reply[1] = buf[1];                                          // client's own ID
    if (sendto(client_fd, reply, static_cast<std::size_t>(m), 0,
               reinterpret_cast<const sockaddr*>(&job.client), job.client_len) < 0) {
        std::perror("sendto (forwarded reply)");
        return;
    }
    ++stats.forwarded;
    if (kLogQueries) std::printf("FORWARDED %s\n", q.name.c_str());
}

// A worker thread: take jobs until the queue is closed and empty.
void worker_loop(WorkQueue<Job>& queue, int client_fd,
                 const Blocklist& blocklist, Stats& stats) {
    while (std::optional<Job> job = queue.pop()) {
        handle_job(*job, client_fd, blocklist, stats);
    }
}

void print_stats(const Stats& stats) {
    std::printf("Stats: received=%llu denied=%llu rate_limited=%llu dropped=%llu "
                "rejected=%llu blocked=%llu forwarded=%llu servfail=%llu\n",
                static_cast<unsigned long long>(stats.received.load()),
                static_cast<unsigned long long>(stats.denied.load()),
                static_cast<unsigned long long>(stats.rate_limited.load()),
                static_cast<unsigned long long>(stats.dropped.load()),
                static_cast<unsigned long long>(stats.rejected.load()),
                static_cast<unsigned long long>(stats.blocked.load()),
                static_cast<unsigned long long>(stats.forwarded.load()),
                static_cast<unsigned long long>(stats.servfail.load()));
}

}  // namespace

int main(int argc, char* argv[]) {
    // Under systemd, stdout goes to the journal through a pipe, which C makes
    // fully buffered -- log lines could sit unseen for a long time, or be lost
    // in a crash. Line buffering writes each line as soon as it's complete.
    std::setvbuf(stdout, nullptr, _IOLBF, 0);

    // ---- Arguments ----------------------------------------------------------
    if (argc > 3) {
        std::fprintf(stderr, "Usage: %s [blocklist-file [allowlist-file]]\n", argv[0]);
        return 1;
    }
    const char* list_path = (argc >= 2) ? argv[1] : "blocklist.txt";
    const char* allow_path = (argc == 3) ? argv[2] : nullptr;   // optional

    // ---- Blocklist: loaded before any thread exists, never modified after ----
    Blocklist blocklist;
    if (!blocklist.load(list_path)) {
        std::fprintf(stderr, "Cannot open blocklist: %s\n", list_path);
        return 1;
    }
    std::printf("Loaded %zu blocked domains (%zu invalid lines skipped)\n",
                blocklist.size(), blocklist.skipped());
    if (allow_path != nullptr) {
        // An allowlist that was asked for but can't be read is an error, not
        // something to silently ignore.
        if (!blocklist.load_allowlist(allow_path)) {
            std::fprintf(stderr, "Cannot open allowlist: %s\n", allow_path);
            return 1;
        }
        std::printf("Loaded %zu allowed domains (%zu invalid lines skipped)\n",
                    blocklist.allow_size(), blocklist.allow_skipped());
    }
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

    // ---- Access control -----------------------------------------------------
    std::vector<Ipv4Net> allowed;
    for (const char* text : kAllowedNets) {
        Ipv4Net n;
        if (!parse_ipv4_net(text, n)) {
            std::fprintf(stderr, "Invalid allowed subnet: %s\n", text);
            return 1;
        }
        allowed.push_back(n);
    }
    RateLimiter limiter(kRatePerSec, kBurst, kMaxTrackedClients);

    // ---- Client-facing socket -------------------------------------------------
    int client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (client_fd < 0) { std::perror("socket"); return 1; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    if (inet_pton(AF_INET, kBindIp, &addr.sin_addr) != 1) {
        std::fprintf(stderr, "Invalid bind address: %s\n", kBindIp);
        close(client_fd); return 1;
    }
    if (bind(client_fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0) {
        std::perror("bind"); close(client_fd); return 1;
    }
    // A 1-second receive timeout so the receiver re-checks g_stop and the
    // stats timer regularly, even when no queries arrive.
    timeval rtv{};
    rtv.tv_sec = 1;
    if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof rtv) < 0) {
        std::perror("setsockopt (client timeout)"); close(client_fd); return 1;
    }

    // ---- Check the upstream address once, so a typo fails at startup -------
    {
        int probe = make_upstream_socket();
        if (probe < 0) { close(client_fd); return 1; }
        close(probe);
    }

    // ---- Start workers -----------------------------------------------------------
    WorkQueue<Job> queue(kQueueCapacity);
    Stats stats;
    std::vector<std::thread> workers;

    // Block SIGINT/SIGTERM while creating workers: new threads inherit the
    // mask, so these signals can only be delivered to this (receiver) thread,
    // where they interrupt recvfrom() and stop the loop immediately.
    sigset_t stop_signals, old_mask;
    sigemptyset(&stop_signals);
    sigaddset(&stop_signals, SIGINT);
    sigaddset(&stop_signals, SIGTERM);
    if (pthread_sigmask(SIG_BLOCK, &stop_signals, &old_mask) != 0) {
        std::fprintf(stderr, "pthread_sigmask failed\n");
        close(client_fd); return 1;
    }
    bool started = true;
    try {
        for (unsigned i = 0; i < kWorkers; ++i) {
            workers.emplace_back(worker_loop, std::ref(queue), client_fd,
                                 std::cref(blocklist), std::ref(stats));
        }
    } catch (const std::system_error& e) {
        std::fprintf(stderr, "Failed to start worker thread: %s\n", e.what());
        started = false;
    }
    if (pthread_sigmask(SIG_SETMASK, &old_mask, nullptr) != 0) {
        std::fprintf(stderr, "pthread_sigmask restore failed\n");
        started = false;
    }
    if (!started) {
        queue.close();
        for (std::thread& t : workers) t.join();
        close(client_fd);
        return 1;
    }

    std::printf("Listening on %s:%u with %u workers, forwarding to %s\n",
                kBindIp, kPort, kWorkers, kUpstreamIp);

    // ---- Receiver loop (this thread) -------------------------------------------
    uint8_t buf[4096];
    auto next_stats = RateLimiter::Clock::now() + std::chrono::seconds(kStatsIntervalSec);
    while (!g_stop.load()) {
        // The 1-second receive timeout guarantees this check runs regularly
        // even when no queries arrive.
        if (RateLimiter::Clock::now() >= next_stats) {
            print_stats(stats);
            next_stats += std::chrono::seconds(kStatsIntervalSec);
        }

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

        // Access control happens here, before any parsing or queueing, so
        // unwanted traffic costs almost nothing. Denied packets are counted,
        // not logged: logging each one would let a flood fill the log.
        if (job.client_len != sizeof(sockaddr_in) || job.client.sin_family != AF_INET) {
            ++stats.denied;
            continue;
        }
        const uint32_t src = ntohl(job.client.sin_addr.s_addr);
        bool permitted = false;
        for (const Ipv4Net& net : allowed) {
            if (net_contains(net, src)) { permitted = true; break; }
        }
        if (!permitted) { ++stats.denied; continue; }
        if (!limiter.allow(src, RateLimiter::Clock::now())) {
            ++stats.rate_limited;
            continue;
        }

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
    close(client_fd);

    print_stats(stats);
    return 0;
}
