#pragma once
// access_control.hpp -- who may use the server, and how fast.
//
// Two layers, both applied by the receiver thread BEFORE a packet is queued:
//   1. An allow-list of IPv4 subnets. Anything else is silently dropped, so
//      the server can never act as an open resolver.
//   2. A per-client token-bucket rate limiter, so one device (or one
//      attacker inside the network) can't monopolize the workers.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <unordered_map>

// An IPv4 subnet such as 10.0.0.0/24. Addresses are in host byte order.
struct Ipv4Net {
    uint32_t net = 0;
    uint32_t mask = 0;
};

// Parses "a.b.c.d/prefix". Rejects malformed text, prefixes outside 8-32
// (so "0.0.0.0/0" -- the whole internet -- can never be allowed by accident),
// and addresses with host bits set (e.g. "10.0.0.5/24" -- almost always a typo).
bool parse_ipv4_net(const char* text, Ipv4Net& out);

inline bool net_contains(const Ipv4Net& n, uint32_t addr) {
    return (addr & n.mask) == n.net;
}

// Token bucket per client: each client may send `burst` queries at once,
// refilled at `rate_per_sec`. NOT thread-safe: used only by the receiver.
class RateLimiter {
public:
    using Clock = std::chrono::steady_clock;   // monotonic: immune to clock changes

    RateLimiter(double rate_per_sec, double burst, std::size_t max_clients);

    // Returns true if this client may send one more query now.
    bool allow(uint32_t addr, Clock::time_point now);

private:
    struct Bucket {
        double tokens;
        Clock::time_point last;
    };
    void evict_idle(Clock::time_point now);

    double rate_;
    double burst_;
    std::size_t max_clients_;
    std::unordered_map<uint32_t, Bucket> buckets_;
};
