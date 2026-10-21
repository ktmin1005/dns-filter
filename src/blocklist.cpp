// blocklist.cpp -- loading and matching blocked domains.

#include "blocklist.hpp"

#include <cctype>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>

namespace {

// Resource limits: even a corrupted or malicious blocklist file can't make
// the server use unbounded memory. Real lists are ~100k-300k entries.
constexpr std::size_t kMaxEntries = 2'000'000;
constexpr std::size_t kMaxLineLength = 1024;

// Returns true only for a well-formed domain name:
//   - total length 1-253, at least two labels (rejects "com", "localhost")
//   - each label 1-63 chars of a-z, 0-9, '-', '_'
//   - no label starts or ends with '-'
//   - the last label (TLD) contains a letter (rejects "0.0.0.0", IPs)
// The input must already be lowercase.
bool valid_domain(const std::string& s) {
    if (s.empty() || s.size() > 253) return false;
    std::size_t labels = 0;
    std::size_t start = 0;
    while (true) {
        std::size_t end = s.find('.', start);
        if (end == std::string::npos) end = s.size();
        std::size_t len = end - start;
        if (len == 0 || len > 63) return false;           // empty or oversized label
        if (s[start] == '-' || s[end - 1] == '-') return false;
        bool has_alpha = false;
        for (std::size_t i = start; i < end; ++i) {
            char c = s[i];
            if (c >= 'a' && c <= 'z') {
                has_alpha = true;
            } else if (!((c >= '0' && c <= '9') || c == '-' || c == '_')) {
                return false;                             // any other character
            }
        }
        ++labels;
        if (end == s.size()) return labels >= 2 && has_alpha;
        start = end + 1;
    }
}

// Reads and validates one list file into `out`. Shared by the blocklist and
// the allowlist so both get exactly the same validation and limits.
bool load_list(const std::string& path, std::unordered_set<std::string>& out,
               std::size_t& skipped, bool& hit_limit) {
    std::ifstream in(path);
    if (!in) return false;

    out.clear();
    skipped = 0;
    hit_limit = false;

    std::string line;
    while (std::getline(in, line)) {
        if (line.size() > kMaxLineLength) { ++skipped; continue; }

        // Strip comments: everything from '#' onward.
        if (std::size_t hash = line.find('#'); hash != std::string::npos) {
            line.erase(hash);
        }

        // Split on whitespace (this also handles Windows "\r\n" endings).
        std::istringstream fields(line);
        std::string first, second, extra;
        if (!(fields >> first)) continue;                 // blank or comment-only line

        std::string domain = first;
        if (fields >> second) {
            // Hosts-file format: "<ip> <domain>". Only accept the sinkhole
            // addresses blocklists use; anything else is not a list entry.
            if (first != "0.0.0.0" && first != "127.0.0.1") { ++skipped; continue; }
            if (fields >> extra) { ++skipped; continue; }  // more fields than expected
            domain = second;
        }

        for (char& c : domain) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        if (!domain.empty() && domain.back() == '.') domain.pop_back();  // "example.com."

        if (!valid_domain(domain)) { ++skipped; continue; }

        if (out.size() >= kMaxEntries) { hit_limit = true; break; }
        out.insert(std::move(domain));
    }
    return true;
}

// True if `name` or any parent domain of it is in `set`, cutting only at dots:
// "a.ads.example.com" -> "ads.example.com" -> "example.com" -> "com".
bool matches_suffix(const std::unordered_set<std::string>& set, const std::string& name) {
    if (set.empty()) return false;
    std::size_t pos = 0;
    while (true) {
        if (set.count(name.substr(pos)) != 0) return true;
        std::size_t dot = name.find('.', pos);
        if (dot == std::string::npos) return false;
        pos = dot + 1;
    }
}

}  // namespace

bool Blocklist::load(const std::string& path) {
    return load_list(path, blocked_, skipped_, hit_limit_);
}

bool Blocklist::load_allowlist(const std::string& path) {
    bool allow_hit_limit = false;
    bool ok = load_list(path, allowed_, allow_skipped_, allow_hit_limit);
    if (allow_hit_limit) hit_limit_ = true;
    return ok;
}

bool Blocklist::is_blocked(const std::string& name) const {
    // The allowlist wins: it exists to correct false positives.
    if (matches_suffix(allowed_, name)) return false;
    return matches_suffix(blocked_, name);
}
