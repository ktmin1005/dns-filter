#pragma once
// blocklist.hpp -- the set of blocked domains.
//
// A query is blocked if its name, or any parent domain of it, is in the set.
// Example: if "doubleclick.net" is listed, then "ad.doubleclick.net" and
// "x.y.doubleclick.net" are blocked too -- but "notdoubleclick.net" is NOT,
// because matching happens only at label (dot) boundaries.

#include <cstddef>
#include <string>
#include <unordered_set>

class Blocklist {
public:
    // Loads domains from a file (one per line, or hosts-file format
    // "0.0.0.0 domain"). Returns false if the file can't be opened.
    // Every line is validated; anything malformed is skipped and counted,
    // never trusted.
    bool load(const std::string& path);

    // `name` must already be lowercase -- the DNS parser guarantees this.
    bool is_blocked(const std::string& name) const;

    std::size_t size() const { return domains_.size(); }
    std::size_t skipped() const { return skipped_; }
    bool hit_limit() const { return hit_limit_; }

private:
    std::unordered_set<std::string> domains_;
    std::size_t skipped_ = 0;
    bool hit_limit_ = false;
};
