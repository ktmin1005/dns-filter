// dot_client.cpp -- DNS over TLS (RFC 7858) client connections.

#include "dot_client.hpp"

#include <arpa/inet.h>      // inet_pton, htons
#include <netinet/in.h>     // sockaddr_in
#include <netinet/tcp.h>    // TCP_NODELAY
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>   // std::copy
#include <cstdio>
#include <utility>

DotContext::DotContext() {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) return;

    // TLS 1.3 only: every older version has known weaknesses or weaker
    // defaults, and the resolvers we use all support 1.3.
    // Verify the server's certificate against the OS trust store; a
    // connection whose certificate fails is refused, never used.
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_default_verify_paths(ctx) != 1) {
        SSL_CTX_free(ctx);
        return;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    ctx_ = ctx;
}

DotContext::~DotContext() {
    if (ctx_ != nullptr) SSL_CTX_free(ctx_);
}

DotConnection::DotConnection(const DotContext& ctx, std::string ip, std::string tls_name,
                             int timeout_sec)
    : ctx_(ctx), ip_(std::move(ip)), tls_name_(std::move(tls_name)),
      timeout_sec_(timeout_sec) {}

DotConnection::~DotConnection() { close_conn(); }

void DotConnection::close_conn() {
    if (ssl_ != nullptr) {
        // No SSL_shutdown(): it would wait on the network for a peer that
        // may already be gone. Freeing is enough for a client.
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
}

bool DotConnection::open() {
    close_conn();
    ERR_clear_error();

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(853);                       // DNS over TLS port
    if (inet_pton(AF_INET, ip_.c_str(), &addr.sin_addr) != 1) return false;

    fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) return false;

    // Timeouts on every blocking step. On Linux, SO_SNDTIMEO also bounds
    // connect(); SO_RCVTIMEO bounds each read, including during the handshake.
    timeval tv{};
    tv.tv_sec = timeout_sec_;
    int one = 1;
    if (setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0 ||
        setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) < 0 ||
        setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) < 0) {
        close_conn();
        return false;
    }
    if (connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0) {
        close_conn();
        return false;
    }

    ssl_ = SSL_new(ctx_.get());
    if (ssl_ == nullptr ||
        SSL_set_fd(ssl_, fd_) != 1 ||
        // SNI: tell the server which certificate we expect.
        SSL_set_tlsext_host_name(ssl_, tls_name_.c_str()) != 1 ||
        // Hostname verification: the certificate must be issued for this
        // exact name. Without this step, ANY valid certificate -- including
        // one an attacker legitimately bought for their own domain -- would
        // be accepted, and TLS would protect nothing.
        SSL_set1_host(ssl_, tls_name_.c_str()) != 1) {
        close_conn();
        return false;
    }

    if (SSL_connect(ssl_) != 1) {
        long result = SSL_get_verify_result(ssl_);
        if (result != X509_V_OK) {
            std::fprintf(stderr, "DoT: certificate verification failed for %s: %s\n",
                         tls_name_.c_str(), X509_verify_cert_error_string(result));
        } else {
            std::fprintf(stderr, "DoT: TLS handshake with %s failed\n", ip_.c_str());
        }
        close_conn();
        return false;
    }
    // Belt and braces: confirm verification succeeded even though
    // SSL_VERIFY_PEER already makes a failed check abort the handshake.
    if (SSL_get_verify_result(ssl_) != X509_V_OK) {
        close_conn();
        return false;
    }
    return true;
}

bool DotConnection::write_all(const uint8_t* data, std::size_t len) {
    while (len > 0) {
        std::size_t written = 0;
        if (SSL_write_ex(ssl_, data, len, &written) != 1) return false;
        data += written;
        len -= written;
    }
    return true;
}

bool DotConnection::read_all(uint8_t* data, std::size_t len) {
    while (len > 0) {
        std::size_t got = 0;
        if (SSL_read_ex(ssl_, data, len, &got) != 1) return false;   // timeout, close, or error
        data += got;
        len -= got;
    }
    return true;
}

ssize_t DotConnection::exchange(const uint8_t* query, std::size_t query_len,
                                uint8_t* resp, std::size_t resp_cap) {
    // DNS over TCP/TLS frames each message with a 2-byte big-endian length.
    if (query_len == 0 || query_len > 4096) return -1;
    uint8_t frame[2 + 4096];
    frame[0] = static_cast<uint8_t>(query_len >> 8);
    frame[1] = static_cast<uint8_t>(query_len & 0xFF);
    std::copy(query, query + query_len, frame + 2);

    // A reused connection may have been closed by the server while idle,
    // which only shows up when we use it. In that case -- and only then --
    // reconnect and try once more. A brand-new connection that fails is a
    // real failure and isn't retried.
    for (int attempt = 0; attempt < 2; ++attempt) {
        bool reused = (ssl_ != nullptr);
        if (!reused && !open()) return -1;

        uint8_t len_bytes[2];
        if (write_all(frame, 2 + query_len) && read_all(len_bytes, 2)) {
            std::size_t resp_len = (static_cast<std::size_t>(len_bytes[0]) << 8) | len_bytes[1];
            // Reject sizes we can't hold. The connection is now out of sync
            // (the rest of that message is still unread), so drop it.
            if (resp_len == 0 || resp_len > resp_cap) { close_conn(); return -1; }
            if (read_all(resp, resp_len)) return static_cast<ssize_t>(resp_len);
        }
        close_conn();
        if (!reused) return -1;
    }
    return -1;
}
