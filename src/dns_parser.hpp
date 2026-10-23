#pragma once
// dns_parser.hpp -- validates and parses a raw DNS query.
//
// parse_query() is the only code that touches untrusted packet bytes.
// It reads only buf[0..len) and either fills a DnsQuery or says exactly
// why the packet was rejected.

#include <cstddef>
#include <cstdint>
#include <string>

// The parts of a DNS query the filter needs.
struct DnsQuery {
    uint16_t id = 0;
    uint16_t flags = 0;
    std::string name;               // lowercase, dot-separated, no trailing dot
    uint16_t qtype = 0;
    uint16_t qclass = 0;
    std::size_t question_end = 0;   // offset just past QCLASS
    // Largest UDP reply this client accepts: 512 bytes by default, or the
    // size it advertised in an EDNS (OPT) record, clamped to 512-1232.
    std::size_t udp_limit = 512;
};

enum class ParseError {
    None,
    TooShort,            // fewer than 12 bytes: no complete header
    NotQuery,            // QR=1: it's a response
    BadOpcode,           // not a standard query
    BadQuestionCount,    // QDCOUNT != 1
    UnexpectedRecords,   // a query carrying answer/authority records
    MalformedName,       // bad label length, overrun, bad characters, too long
    Truncated,           // name ends before QTYPE/QCLASS
    MalformedOpt,        // EDNS (OPT) record runs past the end of the packet
};

ParseError parse_query(const uint8_t* buf, std::size_t len, DnsQuery& out);

const char* parse_error_text(ParseError e);
