// access_control.cpp -- subnet allow-list parsing and per-client rate limiting.

#include "access_control.hpp"

#include <arpa/inet.h>   // inet_pton, ntohl
#include <netinet/in.h>  // in_addr

#include <algorithm>
#include <charconv>      // from_chars: strict integer parsing, no locale
#include <cstring>
#include <string>

bool parse_ipv4_net(const char* text, Ipv4Net& out) {
    if (text == nullptr) return false;
    const char* slash = std::strchr(text, '/');
    if (slash == nullptr) return false;

    std::string addr_part(text, slash);
    in_addr a{};
    if (inet_pton(AF_INET, addr_part.c_str(), &a) != 1) return false;

    const char* p = slash + 1;
    const char* end = p + std::strlen(p);
    unsigned prefix = 0;
    auto [ptr, ec] = std::from_chars(p, end, prefix);
    if (ec != std::errc() || ptr != end || p == end || prefix > 32) return false;

    // Refuse very broad ranges. "0.0.0.0/0" would allow the entire internet,
    // turning this server into an open resolver -- exactly what the
    // allow-list exists to prevent. No home network needs anything wider than /8.
    if (prefix < 8) return false;

    uint32_t mask = 0xFFFFFFFFu << (32 - prefix);   // prefix >= 8, so shift <= 24
    uint32_t net = ntohl(a.s_addr);
    if ((net & ~mask) != 0) return false;   // host bits set

    out.net = net;
    out.mask = mask;
    return true;
}

RateLimiter::RateLimiter(double rate_per_sec, double burst, std::size_t max_clients)
    : rate_(rate_per_sec), burst_(burst), max_clients_(max_clients) {}

bool RateLimiter::allow(uint32_t addr, Clock::time_point now) {
    auto it = buckets_.find(addr);
    if (it == buckets_.end()) {
        if (buckets_.size() >= max_clients_) {
            evict_idle(now);
            // Table still full: refuse NEW clients rather than grow memory.
            // Known clients keep working.
            if (buckets_.size() >= max_clients_) return false;
        }
        it = buckets_.emplace(addr, Bucket{burst_, now}).first;
    }

    Bucket& b = it->second;
    double elapsed = std::chrono::duration<double>(now - b.last).count();
    b.tokens = std::min(burst_, b.tokens + elapsed * rate_);   // refill, capped
    b.last = now;

    if (b.tokens < 1.0) return false;   // out of tokens: drop this query
    b.tokens -= 1.0;
    return true;
}

void RateLimiter::evict_idle(Clock::time_point now) {
    // A client idle long enough to have refilled completely is
    // indistinguishable from a new one, so forgetting it is harmless.
    const double full_refill_sec = burst_ / rate_;
    for (auto it = buckets_.begin(); it != buckets_.end();) {
        double idle = std::chrono::duration<double>(now - it->second.last).count();
        if (idle >= full_refill_sec) it = buckets_.erase(it);
        else ++it;
    }
}
