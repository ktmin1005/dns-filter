// main.cpp -- multithreaded DNS filtering server (deployed as a systemd service).
// Answers DNS over UDP and TCP; forwards allowed queries upstream over DNS over
// TLS (RFC 7858).
//
// Threads:
//   - UDP receiver (the main thread): reads datagrams, applies the allow-list
//     and per-client rate limit, and queues them for the UDP workers.
//   - UDP workers (kWorkers): validate, block or forward, and reply.
//   - TCP acceptor: accepts connections, applies the allow-list and a
//     per-client connection rate limit, and queues them for the TCP workers.
//   - TCP workers (kTcpWorkers): serve a few queries per connection under
//     strict time limits, using exactly the same query logic as UDP.
//
// Shared state and why it's safe:
//   - Allow-list: built before any thread starts, then only read.
//   - Rate limiters: one per accepting thread (UDP receiver, TCP acceptor),
//     never shared between threads.
//   - Work queues: each protected by its own mutex.
//   - Blocklist: loaded before any thread starts, then only read.
//   - UDP socket: sendto() from several threads is safe; each call sends one
//     complete datagram.
//   - Stats: std::atomic counters.
//   - Upstreams: each worker owns its own TLS connections; the shared
//     DotContext (TLS settings) is read-only after setup.
//   - Stop flag: a lock-free std::atomic<bool>, safe to set from a signal
//     handler and read from other threads.

#include <arpa/inet.h>    // htons, inet_pton, inet_ntop
#include <netinet/in.h>   // sockaddr_in
#include <netinet/tcp.h>  // TCP_NODELAY
#include <pthread.h>      // pthread_sigmask
#include <signal.h>       // sigset_t, sigaction
#include <sys/random.h>   // getrandom
#include <sys/socket.h>   // socket, bind, listen, accept4, send, recv, sendto, recvfrom
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
#include <deque>
#include <functional>     // std::ref, std::cref
#include <optional>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "access_control.hpp"
#include "blocklist.hpp"
#include "dot_client.hpp"
#include "dns_parser.hpp"
#include "work_queue.hpp"

namespace {

using Clock = std::chrono::steady_clock;

// Where the server listens (UDP and TCP). Binding to the Pi's specific LAN
// address (not 0.0.0.0) means it can't be reached through any other
// interface, such as a VPN or a second network adapter. Requires a DHCP
// reservation for this IP.
constexpr const char* kBindIp = "10.0.0.131";
constexpr uint16_t kPort = 53;            // standard DNS port
constexpr bool kDebug = false;            // true = hex dumps and parsed fields
// Per-query log lines (BLOCKED/FORWARDED) record which domains each device
// looks up -- other people's browsing, once they use this server. Off by
// default; periodic counters are logged instead.
constexpr bool kLogQueries = false;
constexpr int kStatsIntervalSec = 300;    // log counters every 5 minutes

// Upstream resolvers, reached only over DNS over TLS on port 853. Their
// certificate must be valid for kUpstreamTlsName or the connection is refused.
// There is deliberately NO fallback to plain DNS: if an attacker could block
// port 853 and make us "fall back", they'd get back everything TLS protects.
// The addresses are tried in order; a failed one is skipped for
// kUpstreamCooldownSec so every query doesn't wait out its timeout. Each
// address must also be listed in IPAddressAllow= in deploy/dnsfilter.service.
constexpr const char* kUpstreamIps[] = {"1.1.1.1", "1.0.0.1"};
constexpr const char* kUpstreamTlsName = "cloudflare-dns.com";
constexpr int kUpstreamCooldownSec = 30;
constexpr int kUpstreamTimeoutSec = 3;    // per connect / handshake / read

constexpr unsigned kWorkers = 4;          // UDP workers: one per Pi 400 core
constexpr std::size_t kQueueCapacity = 256;   // max queued UDP queries (~1 MB worst case)

// DNS over TCP. Clients use it mainly to retry an answer that was too big for
// UDP. A TCP connection costs far more than a datagram, so everything about it
// is bounded: how many wait, how long each may take, and how many queries it
// may carry. A client that stalls or trickles bytes is cut off at the deadline.
constexpr unsigned kTcpWorkers = 2;
constexpr std::size_t kTcpQueueCapacity = 16;  // accepted connections waiting
constexpr int kTcpIoTimeoutSec = 3;            // per read or write
constexpr int kTcpConnectionSec = 10;          // whole-connection deadline
constexpr int kTcpMaxQueries = 8;              // queries per connection
constexpr int kTcpBacklog = 16;                // kernel queue of pending handshakes
// Per-client connection rate: bursts of 20, refilled at one per second.
constexpr double kTcpConnRatePerSec = 1.0;
constexpr double kTcpConnBurst = 20.0;

// Only these subnets may use the server. Everything else is dropped silently.
// This MUST match your home network -- check with: ip -4 addr show
// (Loopback isn't listed: the server only listens on the LAN address, and
// the Pi's own queries to that address come from 10.0.0.131, which is inside.)
constexpr const char* kAllowedNets[] = {"10.0.0.0/24"};

// Per-client UDP rate limit: up to 1000 queries per minute (a burst of 1000,
// refilled at 1000/60 per second). Measured on real browsing: a burst limit
// of 100 throttled normal use -- a busy page plus background apps can issue
// hundreds of lookups in seconds, and every dropped query triggers a client
// retry, which makes the burst bigger. 1000/minute matches the default used
// by Pi-hole and still stops a single device from flooding the server.
constexpr double kRatePerSec = 1000.0 / 60.0;
constexpr double kBurst = 1000.0;
constexpr std::size_t kMaxTrackedClients = 1024;

constexpr uint16_t kRcodeFormerr = 1;      // format error: the query was malformed
constexpr uint16_t kRcodeServfail = 2;
constexpr uint16_t kRcodeNxdomain = 3;
constexpr uint16_t kRcodeNotimp = 4;       // not implemented: unsupported opcode

// Every reply buffer holds the largest possible DNS message (the 2-byte
// length prefix used over TCP/TLS can't express more than this).
constexpr std::size_t kMaxMessage = 65535;

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
// other threads. A lock-free atomic is both async-signal-safe and safe to
// share between threads; `volatile sig_atomic_t` is only guaranteed for a
// handler and code on the SAME thread, so it would be a data race here.
std::atomic<bool> g_stop{false};
static_assert(std::atomic<bool>::is_always_lock_free,
              "the stop flag must be lock-free to be set from a signal handler");

extern "C" void handle_stop_signal(int) { g_stop.store(true); }

// One received UDP datagram waiting to be handled.
struct Job {
    std::vector<uint8_t> packet;   // exactly the bytes received
    sockaddr_in client{};
    socklen_t client_len = 0;
};

// One accepted TCP connection waiting to be served. The queue owns the
// descriptor until a TCP worker takes it.
struct TcpConn {
    int fd = -1;
    char ip[INET_ADDRSTRLEN] = "?";
};

struct Stats {
    std::atomic<uint64_t> received{0};      // UDP datagrams + TCP queries
    std::atomic<uint64_t> denied{0};        // source not in an allowed subnet
    std::atomic<uint64_t> rate_limited{0};  // UDP queries or TCP connections over the limit
    std::atomic<uint64_t> dropped{0};       // UDP queue full
    std::atomic<uint64_t> rejected{0};      // failed validation
    std::atomic<uint64_t> blocked{0};
    std::atomic<uint64_t> forwarded{0};
    std::atomic<uint64_t> servfail{0};
    std::atomic<uint64_t> truncated{0};     // UDP reply too big for the client's limit
    std::atomic<uint64_t> failover{0};      // answered by a backup upstream
    std::atomic<uint64_t> tcp_accepted{0};  // TCP connections served
    std::atomic<uint64_t> tcp_refused{0};   // TCP connections closed unserved (queue full, setup error)
};

// Closes a file descriptor when it goes out of scope, on every return path.
struct FdGuard {
    int fd;
    explicit FdGuard(int f) : fd(f) {}
    ~FdGuard() { if (fd >= 0) close(fd); }
    FdGuard(const FdGuard&) = delete;
    FdGuard& operator=(const FdGuard&) = delete;
};

// Formats an IPv4 address for log lines ("?" if that somehow fails).
void format_ip(const in_addr& a, char (&out)[INET_ADDRSTRLEN]) {
    if (inet_ntop(AF_INET, &a, out, sizeof out) == nullptr) std::memcpy(out, "?", 2);
}

bool is_allowed(const std::vector<Ipv4Net>& allowed, uint32_t addr) {
    for (const Ipv4Net& net : allowed) {
        if (net_contains(net, addr)) return true;
    }
    return false;
}

// ---- Reply builders --------------------------------------------------------
// Each writes a complete reply into `out` (capacity `cap`, always >= 4096 here)
// and returns its length, or 0 if it doesn't fit. parse_query() guarantees
// q.question_end <= the query length <= 4096.

// Header and question with the given RCODE; for blocked names, also the
// synthetic SOA record so clients can cache the block.
std::size_t build_error(uint8_t* out, std::size_t cap, const uint8_t* query,
                        const DnsQuery& q, uint16_t rcode, bool with_soa) {
    if (q.question_end > cap) return 0;
    std::memcpy(out, query, q.question_end);
    // QR=1, copy RD, RA=1, RCODE. Opcode 0, AA/TC/AD all 0.
    uint16_t f = 0x8000 | (q.flags & 0x0100) | 0x0080 | rcode;
    out[2] = static_cast<uint8_t>(f >> 8);
    out[3] = static_cast<uint8_t>(f & 0xFF);
    std::memset(&out[6], 0, 6);             // ANCOUNT, NSCOUNT, ARCOUNT = 0

    std::size_t len = q.question_end;
    if (with_soa && len + sizeof kBlockedSoa <= cap) {
        std::memcpy(out + len, kBlockedSoa, sizeof kBlockedSoa);
        len += sizeof kBlockedSoa;
        out[9] = 1;                         // NSCOUNT = 1 (low byte; high byte is 0)
    }
    return len;
}

// A bare 12-byte header with the given RCODE, for malformed queries.
// - No question is echoed back: the question is the part that failed
//   validation, so none of it is trusted or repeated.
// - The reply is never larger than the query (which had at least 12 bytes),
//   so it can't be used to amplify traffic.
// Callers must guarantee the query is at least 12 bytes long.
std::size_t build_header_only(uint8_t* out, const uint8_t* query, uint16_t rcode) {
    out[0] = query[0];                      // echo the ID so the client
    out[1] = query[1];                      // can match the reply
    uint16_t qflags = static_cast<uint16_t>((query[2] << 8) | query[3]);
    // QR=1, copy the opcode and RD, RA=1, RCODE. AA/TC/AD all 0.
    uint16_t f = 0x8000 | (qflags & 0x7800) | (qflags & 0x0100) | 0x0080 | rcode;
    out[2] = static_cast<uint8_t>(f >> 8);
    out[3] = static_cast<uint8_t>(f & 0xFF);
    std::memset(&out[4], 0, 8);             // QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = 0
    return 12;
}

// Header and question with TC (truncated) set and no records: "too big for
// UDP, ask again over TCP".
std::size_t build_truncated(uint8_t* out, std::size_t cap, const uint8_t* query,
                            const DnsQuery& q) {
    if (q.question_end > cap) return 0;
    std::memcpy(out, query, q.question_end);
    // QR=1, TC=1, copy RD, RA=1, RCODE=0.
    uint16_t f = 0x8000 | 0x0200 | (q.flags & 0x0100) | 0x0080;
    out[2] = static_cast<uint8_t>(f >> 8);
    out[3] = static_cast<uint8_t>(f & 0xFF);
    std::memset(&out[6], 0, 6);             // ANCOUNT, NSCOUNT, ARCOUNT = 0
    return q.question_end;
}

void hex_dump(const uint8_t* data, std::size_t len) {
    for (std::size_t i = 0; i < len; ++i) {
        if (i % 16 == 0) std::printf("%04zx:  ", i);
        std::printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) std::printf("\n");
    }
    std::printf("\n");
}

// One upstream resolver as seen by one worker: its TLS connection, plus the
// time until which it's skipped after a failure.
struct Upstream {
    const char* ip;
    DotConnection conn;
    Clock::time_point skip_until{};

    Upstream(const DotContext& tls, const char* addr)
        : ip(addr), conn(tls, addr, kUpstreamTlsName, kUpstreamTimeoutSec) {}
};

// A worker's upstream set. A deque, not a vector: Upstream can't be moved or
// copied (it owns a live TLS connection), and deque::emplace_back never
// relocates existing items.
std::deque<Upstream> make_upstreams(const DotContext& tls) {
    std::deque<Upstream> ups;
    for (const char* ip : kUpstreamIps) ups.emplace_back(tls, ip);
    return ups;
}

// True if `reply` (length m) is a genuine answer to `out`, the query we sent:
// long enough, our random ID, QR=1, and the exact same question.
bool reply_matches(const uint8_t* reply, ssize_t m, const std::vector<uint8_t>& out,
                   const DnsQuery& q) {
    return m >= 0
        && static_cast<std::size_t>(m) >= q.question_end           // checked first
        && reply[0] == out[0] && reply[1] == out[1]                // our random ID
        && (reply[2] & 0x80)                                       // QR=1
        && std::memcmp(reply + 12, out.data() + 12, q.question_end - 12) == 0;
}

// Logs a failed lookup. The domain name is included only when per-query
// logging is on: failure lines are otherwise a record of what someone looked up.
void log_servfail(const char* what, const DnsQuery& q) {
    if (kLogQueries) std::printf("%s for %s -> SERVFAIL\n", what, q.name.c_str());
    else             std::printf("%s -> SERVFAIL\n", what);
}

enum class Transport { Udp, Tcp };

// Handles one query from start to finish, for either transport, and writes
// the reply into `reply` (capacity reply_cap >= 4096). Returns the reply's
// length, or 0 when no reply should be sent.
std::size_t process_query(const uint8_t* buf, std::size_t n, const char* ip,
                          Transport transport, std::deque<Upstream>& upstreams,
                          uint8_t* reply, std::size_t reply_cap,
                          const Blocklist& blocklist, Stats& stats) {
    if (reply_cap < 4096) return 0;
    if (kDebug) {
        std::printf("Received %zu bytes from %s over %s\n", n, ip,
                    transport == Transport::Udp ? "UDP" : "TCP");
        hex_dump(buf, n);
    }

    DnsQuery q;
    ParseError err = parse_query(buf, n, q);
    if (err != ParseError::None) {
        ++stats.rejected;
        std::printf("REJECTED packet from %s: %s\n", ip, parse_error_text(err));
        switch (err) {
            case ParseError::BadOpcode:
                return build_header_only(reply, buf, kRcodeNotimp);
            case ParseError::BadQuestionCount:
            case ParseError::UnexpectedRecords:
            case ParseError::MalformedName:
            case ParseError::Truncated:
            case ParseError::MalformedOpt:
                return build_header_only(reply, buf, kRcodeFormerr);
            case ParseError::TooShort:      // under 12 bytes: no full header to answer
            case ParseError::NotQuery:      // never answer a response: prevents reply loops
            case ParseError::None:
                return 0;
        }
        return 0;
    }
    if (kDebug) {
        std::printf("ID=%u RD=%d Name=%s QTYPE=%u\n", static_cast<unsigned>(q.id),
                    (q.flags & 0x0100) ? 1 : 0, q.name.c_str(),
                    static_cast<unsigned>(q.qtype));
    }

    // ---- Blocked: answer NXDOMAIN ourselves ---------------------------------
    if (blocklist.is_blocked(q.name)) {
        ++stats.blocked;
        if (kLogQueries) std::printf("BLOCKED %s\n", q.name.c_str());
        return build_error(reply, reply_cap, buf, q, kRcodeNxdomain, true);
    }

    // ---- Allowed: forward over DNS over TLS --------------------------------
    // The query carries a fresh random ID (from the OS's secure generator)
    // rather than the client's, so even a client with weak IDs can't make
    // replies predictable. TLS already authenticates the resolver; the ID and
    // question checks are defense in depth.
    uint16_t upstream_id = 0;
    if (getrandom(&upstream_id, sizeof upstream_id, 0) != sizeof upstream_id) {
        ++stats.servfail;
        log_servfail("Random ID failed", q);
        return build_error(reply, reply_cap, buf, q, kRcodeServfail, false);
    }
    std::vector<uint8_t> out(buf, buf + n);              // forwarded copy
    out[0] = static_cast<uint8_t>(upstream_id >> 8);
    out[1] = static_cast<uint8_t>(upstream_id & 0xFF);

    // Try each upstream in order, skipping any that failed recently. If every
    // one is cooling down, try them all anyway rather than fail without trying.
    ssize_t m = -1;
    bool valid = false;
    const auto now = Clock::now();
    for (int pass = 0; pass < 2 && !valid; ++pass) {
        bool attempted = false;
        for (std::size_t i = 0; i < upstreams.size() && !valid; ++i) {
            Upstream& up = upstreams[i];
            if (pass == 0 && now < up.skip_until) continue;   // recently failed
            attempted = true;
            m = up.conn.exchange(out.data(), out.size(), reply, reply_cap);
            valid = reply_matches(reply, m, out, q);
            if (valid) {
                up.skip_until = {};
                if (i > 0) ++stats.failover;
            } else {
                up.skip_until = now + std::chrono::seconds(kUpstreamCooldownSec);
                std::printf("Upstream %s failed; skipping it for %d s\n", up.ip,
                            kUpstreamCooldownSec);
            }
        }
        if (attempted) break;            // pass 0 tried something: don't retry all
    }
    if (!valid) {
        ++stats.servfail;
        log_servfail("Upstream failed", q);
        return build_error(reply, reply_cap, buf, q, kRcodeServfail, false);
    }
    reply[0] = buf[0];                   // restore the
    reply[1] = buf[1];                   // client's own ID

    // Over TLS the resolver sends the full answer whatever its size, but a UDP
    // client only accepts q.udp_limit bytes. Bigger answers get the standard
    // "truncated" reply; the client then asks again over TCP, where the full
    // answer is sent.
    if (transport == Transport::Udp && static_cast<std::size_t>(m) > q.udp_limit) {
        ++stats.truncated;
        return build_truncated(reply, reply_cap, buf, q);
    }
    ++stats.forwarded;
    if (kLogQueries) std::printf("FORWARDED %s\n", q.name.c_str());
    return static_cast<std::size_t>(m);
}

// ---- UDP -------------------------------------------------------------------

// A UDP worker thread: take datagrams until the queue is closed and empty.
void udp_worker(WorkQueue<Job>& queue, int udp_fd, const DotContext& tls,
                const Blocklist& blocklist, Stats& stats) {
    std::deque<Upstream> upstreams = make_upstreams(tls);
    std::vector<uint8_t> reply(kMaxMessage);
    while (std::optional<Job> job = queue.pop()) {
        char ip[INET_ADDRSTRLEN];
        format_ip(job->client.sin_addr, ip);
        std::size_t len = process_query(job->packet.data(), job->packet.size(), ip,
                                        Transport::Udp, upstreams, reply.data(),
                                        reply.size(), blocklist, stats);
        if (len > 0 &&
            sendto(udp_fd, reply.data(), len, 0,
                   reinterpret_cast<const sockaddr*>(&job->client), job->client_len) < 0) {
            std::perror("sendto (UDP reply)");
        }
    }
}

// ---- TCP -------------------------------------------------------------------

// Reads exactly `len` bytes. Fails on EOF, error, the per-read timeout
// (SO_RCVTIMEO), or the connection's overall deadline -- so a client that
// trickles one byte at a time can't hold a worker past the deadline.
bool tcp_read_exact(int fd, uint8_t* p, std::size_t len, Clock::time_point deadline) {
    while (len > 0) {
        if (Clock::now() >= deadline) return false;
        ssize_t r = recv(fd, p, len, 0);
        if (r > 0) { p += r; len -= static_cast<std::size_t>(r); continue; }
        if (r < 0 && errno == EINTR) continue;
        return false;                       // 0 = client closed; <0 = timeout or error
    }
    return true;
}

// Writes all `len` bytes under the same limits. MSG_NOSIGNAL: writing to a
// connection the client already closed returns an error instead of raising
// SIGPIPE.
bool tcp_write_all(int fd, const uint8_t* p, std::size_t len, Clock::time_point deadline) {
    while (len > 0) {
        if (Clock::now() >= deadline) return false;
        ssize_t w = send(fd, p, len, MSG_NOSIGNAL);
        if (w > 0) { p += w; len -= static_cast<std::size_t>(w); continue; }
        if (w < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

// Serves up to kTcpMaxQueries queries on one connection. Each message is
// framed by a 2-byte big-endian length (RFC 1035 section 4.2.2). Any framing
// problem, timeout, or query that gets no reply ends the connection.
void serve_tcp_connection(const TcpConn& conn, std::deque<Upstream>& upstreams,
                          std::vector<uint8_t>& frame, const Blocklist& blocklist,
                          Stats& stats) {
    const auto deadline = Clock::now() + std::chrono::seconds(kTcpConnectionSec);
    uint8_t query[4096];                    // same limit as a UDP query
    for (int i = 0; i < kTcpMaxQueries; ++i) {
        uint8_t len_bytes[2];
        if (!tcp_read_exact(conn.fd, len_bytes, 2, deadline)) return;
        const std::size_t qlen = (static_cast<std::size_t>(len_bytes[0]) << 8) | len_bytes[1];
        if (qlen == 0 || qlen > sizeof query) return;   // empty or oversize: hang up
        if (!tcp_read_exact(conn.fd, query, qlen, deadline)) return;
        ++stats.received;

        // The reply is built 2 bytes into `frame`, leaving room for its length.
        std::size_t rlen = process_query(query, qlen, conn.ip, Transport::Tcp, upstreams,
                                         frame.data() + 2, frame.size() - 2,
                                         blocklist, stats);
        if (rlen == 0) return;
        frame[0] = static_cast<uint8_t>(rlen >> 8);
        frame[1] = static_cast<uint8_t>(rlen & 0xFF);
        if (!tcp_write_all(conn.fd, frame.data(), rlen + 2, deadline)) return;
    }
}

// A TCP worker thread: take connections until the queue is closed and empty.
void tcp_worker(WorkQueue<TcpConn>& queue, const DotContext& tls,
                const Blocklist& blocklist, Stats& stats) {
    std::deque<Upstream> upstreams = make_upstreams(tls);
    std::vector<uint8_t> frame(2 + kMaxMessage);
    while (std::optional<TcpConn> conn = queue.pop()) {
        FdGuard guard(conn->fd);            // closed when this connection is done
        serve_tcp_connection(*conn, upstreams, frame, blocklist, stats);
    }
}

// The TCP acceptor thread. Access control happens before a connection is
// queued; refused connections are closed immediately and counted, not logged.
void tcp_acceptor(int listen_fd, const std::vector<Ipv4Net>& allowed,
                  WorkQueue<TcpConn>& queue, Stats& stats) {
    RateLimiter limiter(kTcpConnRatePerSec, kTcpConnBurst, kMaxTrackedClients);
    while (!g_stop.load()) {
        sockaddr_in peer{};
        socklen_t peer_len = sizeof peer;
        int fd = accept4(listen_fd, reinterpret_cast<sockaddr*>(&peer), &peer_len,
                         SOCK_CLOEXEC);
        if (fd < 0) {
            // Timeout (to re-check g_stop), signal, or a client that gave up
            // during the handshake: not errors.
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ||
                errno == ECONNABORTED) continue;
            std::perror("accept");
            continue;
        }
        FdGuard guard(fd);

        if (peer_len != sizeof(sockaddr_in) || peer.sin_family != AF_INET) {
            ++stats.denied;
            continue;
        }
        const uint32_t src = ntohl(peer.sin_addr.s_addr);
        if (!is_allowed(allowed, src)) { ++stats.denied; continue; }
        if (!limiter.allow(src, Clock::now())) { ++stats.rate_limited; continue; }

        timeval tv{};
        tv.tv_sec = kTcpIoTimeoutSec;
        int one = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0 ||
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) < 0 ||
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) < 0) {
            ++stats.tcp_refused;
            continue;
        }

        TcpConn conn;
        conn.fd = fd;
        format_ip(peer.sin_addr, conn.ip);
        if (!queue.try_push(conn)) { ++stats.tcp_refused; continue; }   // guard closes it
        guard.fd = -1;                      // the queue owns it now
        ++stats.tcp_accepted;
    }
}

void print_stats(const Stats& stats) {
    auto v = [](const std::atomic<uint64_t>& a) {
        return static_cast<unsigned long long>(a.load());
    };
    std::printf("Stats: received=%llu denied=%llu rate_limited=%llu dropped=%llu "
                "rejected=%llu blocked=%llu forwarded=%llu servfail=%llu truncated=%llu "
                "failover=%llu tcp_accepted=%llu tcp_refused=%llu\n",
                v(stats.received), v(stats.denied), v(stats.rate_limited), v(stats.dropped),
                v(stats.rejected), v(stats.blocked), v(stats.forwarded), v(stats.servfail),
                v(stats.truncated), v(stats.failover), v(stats.tcp_accepted),
                v(stats.tcp_refused));
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

    // ---- Signals --------------------------------------------------------------
    // Ctrl+C / SIGTERM request a clean shutdown. No SA_RESTART, so a blocked
    // recvfrom() returns early with EINTR.
    struct sigaction sa{};
    sa.sa_handler = handle_stop_signal;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, nullptr) < 0 || sigaction(SIGTERM, &sa, nullptr) < 0) {
        std::perror("sigaction");
        return 1;
    }
    // Writing to a connection the other side already closed raises SIGPIPE,
    // whose default action kills the whole process. Ignore it; the failed
    // write is reported as an error and handled instead.
    struct sigaction ignore_pipe{};
    ignore_pipe.sa_handler = SIG_IGN;
    sigemptyset(&ignore_pipe.sa_mask);
    if (sigaction(SIGPIPE, &ignore_pipe, nullptr) < 0) {
        std::perror("sigaction (SIGPIPE)");
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
    RateLimiter limiter(kRatePerSec, kBurst, kMaxTrackedClients);   // UDP receiver only

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    if (inet_pton(AF_INET, kBindIp, &addr.sin_addr) != 1) {
        std::fprintf(stderr, "Invalid bind address: %s\n", kBindIp);
        return 1;
    }
    // A 1-second receive timeout on both listening sockets, so the UDP
    // receiver and the TCP acceptor re-check g_stop (and the stats timer)
    // regularly, even when nothing arrives.
    timeval one_second{};
    one_second.tv_sec = 1;

    // ---- UDP socket -------------------------------------------------------------
    int udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (udp_fd < 0) { std::perror("socket (UDP)"); return 1; }
    FdGuard udp_guard(udp_fd);
    if (bind(udp_fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0) {
        std::perror("bind (UDP)"); return 1;
    }
    if (setsockopt(udp_fd, SOL_SOCKET, SO_RCVTIMEO, &one_second, sizeof one_second) < 0) {
        std::perror("setsockopt (UDP timeout)"); return 1;
    }

    // ---- TCP listening socket ---------------------------------------------------
    int tcp_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (tcp_fd < 0) { std::perror("socket (TCP)"); return 1; }
    FdGuard tcp_guard(tcp_fd);
    // SO_REUSEADDR lets a restarted server bind while old connections from the
    // previous run are still in TIME_WAIT. (It does not let another program
    // share the port; that would be SO_REUSEPORT, which isn't used.)
    int one = 1;
    if (setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) < 0 ||
        bind(tcp_fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0 ||
        listen(tcp_fd, kTcpBacklog) < 0 ||
        setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, &one_second, sizeof one_second) < 0) {
        std::perror("TCP listening socket"); return 1;
    }

    // ---- TLS --------------------------------------------------------------------
    DotContext tls;
    if (!tls.ok()) {
        std::fprintf(stderr, "Could not set up TLS (DNS over TLS)\n");
        return 1;
    }

    // ---- Start threads ------------------------------------------------------------
    WorkQueue<Job> udp_queue(kQueueCapacity);
    WorkQueue<TcpConn> tcp_queue(kTcpQueueCapacity);
    Stats stats;
    std::vector<std::thread> udp_workers;
    std::vector<std::thread> tcp_workers;
    std::thread acceptor;

    // Block SIGINT/SIGTERM while creating threads: new threads inherit the
    // mask, so these signals can only be delivered to this (UDP receiver)
    // thread, where they interrupt recvfrom() and stop the loop immediately.
    sigset_t stop_signals, old_mask;
    sigemptyset(&stop_signals);
    sigaddset(&stop_signals, SIGINT);
    sigaddset(&stop_signals, SIGTERM);
    if (pthread_sigmask(SIG_BLOCK, &stop_signals, &old_mask) != 0) {
        std::fprintf(stderr, "pthread_sigmask failed\n");
        return 1;
    }
    bool started = true;
    try {
        for (unsigned i = 0; i < kWorkers; ++i) {
            udp_workers.emplace_back(udp_worker, std::ref(udp_queue), udp_fd, std::cref(tls),
                                     std::cref(blocklist), std::ref(stats));
        }
        for (unsigned i = 0; i < kTcpWorkers; ++i) {
            tcp_workers.emplace_back(tcp_worker, std::ref(tcp_queue), std::cref(tls),
                                     std::cref(blocklist), std::ref(stats));
        }
        acceptor = std::thread(tcp_acceptor, tcp_fd, std::cref(allowed),
                               std::ref(tcp_queue), std::ref(stats));
    } catch (const std::system_error& e) {
        std::fprintf(stderr, "Failed to start a thread: %s\n", e.what());
        started = false;
    }
    if (pthread_sigmask(SIG_SETMASK, &old_mask, nullptr) != 0) {
        std::fprintf(stderr, "pthread_sigmask restore failed\n");
        started = false;
    }

    std::vector<uint8_t> buf(4096);
    auto next_stats = Clock::now() + std::chrono::seconds(kStatsIntervalSec);
    if (started) {
        std::printf("Listening on %s:%u (UDP and TCP), %u+%u workers, forwarding over "
                    "TLS to %s, then %s (%s)\n",
                    kBindIp, kPort, kWorkers, kTcpWorkers, kUpstreamIps[0],
                    kUpstreamIps[1], kUpstreamTlsName);
    }

    // ---- UDP receiver loop (this thread) -----------------------------------------
    while (started && !g_stop.load()) {
        if (Clock::now() >= next_stats) {
            print_stats(stats);
            next_stats += std::chrono::seconds(kStatsIntervalSec);
        }

        Job job;
        job.client_len = sizeof job.client;
        ssize_t n = recvfrom(udp_fd, buf.data(), buf.size(), 0,
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
        if (!is_allowed(allowed, src)) { ++stats.denied; continue; }
        if (!limiter.allow(src, Clock::now())) { ++stats.rate_limited; continue; }

        job.packet.assign(buf.data(), buf.data() + n);
        if (!udp_queue.try_push(std::move(job))) {
            // Queue full: drop rather than reply, so a flood can't turn this
            // server into a source of extra traffic.
            ++stats.dropped;
        }
    }

    // ---- Clean shutdown (also the cleanup path if startup failed) -----------------
    if (started) std::printf("\nShutting down: finishing queued queries...\n");
    g_stop.store(true);                   // the acceptor exits within a second
    if (acceptor.joinable()) acceptor.join();
    tcp_queue.close();                    // TCP workers finish their connections, then exit
    for (std::thread& t : tcp_workers) t.join();
    udp_queue.close();                    // UDP workers drain the queue, then exit
    for (std::thread& t : udp_workers) t.join();

    print_stats(stats);
    return started ? 0 : 1;
}
