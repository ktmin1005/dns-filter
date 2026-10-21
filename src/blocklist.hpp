#pragma once
// blocklist.hpp -- the set of blocked domains, plus an allowlist of exceptions.
//
// A query is blocked if its name, or any parent domain of it, is on the
// blocklist -- UNLESS the name or a parent domain is on the allowlist.
// Example: blocklist "doubleclick.net" blocks "ad.doubleclick.net"; adding
// "ad.doubleclick.net" to the allowlist lets that one name (and its
// subdomains) through again. Matching is only at label (dot) boundaries, so
// "notdoubleclick.net" never matches "doubleclick.net".

#include <cstddef>
#include <string>
#include <unordered_set>

class Blocklist {
public:
    // Load domains from a file (one per line, or hosts-file format
    // "0.0.0.0 domain"). Return false if the file can't be opened.
    // Every line is validated; malformed lines are skipped and counted.
    bool load(const std::string& path);
    bool load_allowlist(const std::string& path);

    // `name` must already be lowercase -- the DNS parser guarantees this.
    bool is_blocked(const std::string& name) const;

    std::size_t size() const { return blocked_.size(); }
    std::size_t skipped() const { return skipped_; }
    std::size_t allow_size() const { return allowed_.size(); }
    std::size_t allow_skipped() const { return allow_skipped_; }
    bool hit_limit() const { return hit_limit_; }

private:
    std::unordered_set<std::string> blocked_;
    std::unordered_set<std::string> allowed_;
    std::size_t skipped_ = 0;
    std::size_t allow_skipped_ = 0;
    bool hit_limit_ = false;
};
