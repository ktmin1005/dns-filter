// dns_parser.cpp -- validates and parses a raw DNS query.

#include "dns_parser.hpp"

#include <utility>

namespace {

// Reads a big-endian 16-bit value. Callers must check bounds first.
uint16_t read_u16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

// Lowercases ASCII letters only; leaves every other byte unchanged.
// (Avoids std::tolower, whose behavior can depend on the system locale.)
char ascii_lower(uint8_t c) {
    if (c >= 'A' && c <= 'Z') c = static_cast<uint8_t>(c - 'A' + 'a');
    return static_cast<char>(c);
}

// Allowed inside a label: printable ASCII (0x21-0x7E) except '.'.
// Rejects control characters (terminal/log injection), spaces, bytes >= 0x80,
// and literal dots, which would make one label look like two.
bool allowed_label_byte(uint8_t c) {
    return c >= 0x21 && c <= 0x7E && c != '.';
}

}  // namespace

ParseError parse_query(const uint8_t* buf, std::size_t len, DnsQuery& out) {
    // Header: 12 bytes, all fields big-endian.
    if (len < 12) return ParseError::TooShort;

    uint16_t flags = read_u16(buf + 2);
    if (flags & 0x8000) return ParseError::NotQuery;                 // QR must be 0
    if (((flags >> 11) & 0xF) != 0) return ParseError::BadOpcode;    // opcode 0 only
    if (read_u16(buf + 4) != 1) return ParseError::BadQuestionCount; // QDCOUNT == 1
    if (read_u16(buf + 6) != 0 || read_u16(buf + 8) != 0) {         // ANCOUNT, NSCOUNT == 0
        return ParseError::UnexpectedRecords;
    }
    // ARCOUNT may be nonzero: clients normally include one EDNS (OPT) record.

    // Question name: length-prefixed labels, ending with a zero-length label.
    std::string name;
    std::size_t pos = 12;
    bool terminated = false;
    while (pos < len) {
        uint8_t label_len = buf[pos];
        if (label_len == 0) {                       // end of name
            terminated = true;
            ++pos;
            break;
        }
        // > 63 also rejects compression pointers (first byte 0xC0 and up).
        if (label_len > 63 || pos + 1 + label_len > len) return ParseError::MalformedName;
        if (!name.empty()) name += '.';
        for (std::size_t i = 0; i < label_len; ++i) {
            uint8_t c = buf[pos + 1 + i];
            if (!allowed_label_byte(c)) return ParseError::MalformedName;
            name.push_back(ascii_lower(c));
        }
        pos += 1 + label_len;
    }
    if (!terminated || name.size() > 253) return ParseError::MalformedName;
    // An empty name is the root zone (".") -- unusual but legitimate.

    // QTYPE and QCLASS: 2 bytes each.
    if (pos + 4 > len) return ParseError::Truncated;

    // EDNS: if the first additional record is an OPT record (type 41), its
    // CLASS field is the client's maximum UDP reply size. Anything else in the
    // additional section is left alone (the query is still forwarded intact).
    std::size_t udp_limit = 512;
    const std::size_t after_question = pos + 4;
    if (read_u16(buf + 10) > 0 && after_question + 11 <= len &&
        buf[after_question] == 0 &&                         // owner name: root
        read_u16(buf + after_question + 1) == 41) {          // TYPE = OPT
        const uint16_t advertised = read_u16(buf + after_question + 3);
        const uint16_t rdlength = read_u16(buf + after_question + 9);
        if (after_question + 11 + rdlength > len) return ParseError::MalformedOpt;
        // Capped at 1232 bytes even if the client asks for more: larger UDP
        // replies get split into IP fragments, which some networks drop and
        // which have been used to forge DNS answers. Anything bigger is sent
        // as "truncated", and the client retries over TCP. (1232 is the
        // DNS Flag Day 2020 recommendation.)
        udp_limit = advertised < 512 ? 512 : (advertised > 1232 ? 1232 : advertised);
    }

    out.id = read_u16(buf);
    out.flags = flags;
    out.udp_limit = udp_limit;
    out.name = std::move(name);
    out.qtype = read_u16(buf + pos);
    out.qclass = read_u16(buf + pos + 2);
    out.question_end = pos + 4;
    return ParseError::None;
}

const char* parse_error_text(ParseError e) {
    switch (e) {
        case ParseError::None:              return "ok";
        case ParseError::TooShort:          return "too short for a DNS header";
        case ParseError::NotQuery:          return "not a query (QR=1)";
        case ParseError::BadOpcode:         return "unsupported opcode";
        case ParseError::BadQuestionCount:  return "expected exactly 1 question";
        case ParseError::UnexpectedRecords: return "query contains answer/authority records";
        case ParseError::MalformedName:     return "malformed name";
        case ParseError::Truncated:         return "question truncated (no QTYPE/QCLASS)";
        case ParseError::MalformedOpt:      return "malformed EDNS (OPT) record";
    }
    return "unknown error";
}
