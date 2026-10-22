#pragma once
// dot_client.hpp -- DNS over TLS (RFC 7858) client connections.
//
// Plain DNS crosses the internet unencrypted: anyone on the path (including
// the ISP) can read every lookup and, if well placed, forge answers. DNS over
// TLS sends the same DNS messages inside an authenticated, encrypted TLS
// connection to port 853, so the path sees only "this device talks to
// 1.1.1.1" and cannot read or alter anything.

#include <openssl/ssl.h>
#include <sys/types.h>   // ssize_t

#include <cstddef>
#include <cstdint>
#include <string>

// TLS settings shared by every connection: TLS 1.3 only, and the server's
// certificate must chain to a CA the operating system trusts.
// SSL_CTX is safe to share between threads once configured.
class DotContext {
public:
    DotContext();
    ~DotContext();
    DotContext(const DotContext&) = delete;
    DotContext& operator=(const DotContext&) = delete;

    bool ok() const { return ctx_ != nullptr; }
    SSL_CTX* get() const { return ctx_; }

private:
    SSL_CTX* ctx_ = nullptr;
};

// One TLS connection to an upstream resolver. NOT thread-safe: each worker
// thread owns its own. The connection is opened lazily, kept open for reuse
// (a TLS handshake is far slower than a query), and reopened when it breaks.
class DotConnection {
public:
    // ip: resolver address, e.g. "1.1.1.1".
    // tls_name: the name its certificate must prove, e.g. "cloudflare-dns.com".
    DotConnection(const DotContext& ctx, std::string ip, std::string tls_name,
                  int timeout_sec);
    ~DotConnection();
    DotConnection(const DotConnection&) = delete;
    DotConnection& operator=(const DotConnection&) = delete;

    // Sends one DNS query and reads one response into resp (capacity
    // resp_cap). Returns the response length, or -1 on any failure
    // (connect, handshake, certificate, timeout, oversize response).
    ssize_t exchange(const uint8_t* query, std::size_t query_len,
                     uint8_t* resp, std::size_t resp_cap);

private:
    bool open();
    void close_conn();
    bool write_all(const uint8_t* data, std::size_t len);
    bool read_all(uint8_t* data, std::size_t len);

    const DotContext& ctx_;
    std::string ip_;
    std::string tls_name_;
    int timeout_sec_;
    int fd_ = -1;
    SSL* ssl_ = nullptr;
};
