#include "dpibypass/auto_selector.h"
#include "dpibypass/dpibypass.h"

#include <fstream>
#include <sstream>
#include <chrono>
#include <thread>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>
#endif

namespace dpibypass {

namespace {

socket_t create_tcp_socket() {
    socket_t fd = ::socket(AF_INET, SOCK_STREAM, 0);
    return fd;
}

void close_socket(socket_t fd) {
#ifdef _WIN32
    ::closesocket(fd);
#else
    ::close(fd);
#endif
}

bool set_nonblocking(socket_t fd) {
#ifdef _WIN32
    unsigned long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

void set_blocking(socket_t fd) {
#ifdef _WIN32
    unsigned long mode = 0;
    ioctlsocket(fd, FIONBIO, &mode);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
#endif
}

int connect_with_timeout(socket_t fd, const std::string& host, int port,
                         int timeout_ms) {
    // Returns: 1 = connected, 0 = timeout, -1 = error
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) {
        return -1;
    }

    set_nonblocking(fd);

    int ret = ::connect(fd, res->ai_addr, static_cast<socklen_t>(res->ai_addrlen));
    freeaddrinfo(res);

    if (ret == 0) return 1;

#ifdef _WIN32
    if (WSAGetLastError() != WSAEWOULDBLOCK) return -1;
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ret = select(0, nullptr, &wfds, nullptr, &tv);
#else
    if (errno != EINPROGRESS) return -1;
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;
    ret = poll(&pfd, 1, timeout_ms);
#endif

    if (ret <= 0) return 0;  // timeout

    int err = 0;
    socklen_t errlen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &errlen);
    return err == 0 ? 1 : -1;
}

// Realistic TLS 1.2 ClientHello with common cipher suites and SNI
std::vector<uint8_t> make_probe_hello(const std::string& hostname) {
    // Build SNI extension
    std::vector<uint8_t> sni_ext;
    uint16_t name_len = static_cast<uint16_t>(hostname.size());
    uint16_t list_len = name_len + 3;
    sni_ext.push_back(static_cast<uint8_t>(list_len >> 8));
    sni_ext.push_back(static_cast<uint8_t>(list_len & 0xFF));
    sni_ext.push_back(0x00);  // host_name type
    sni_ext.push_back(static_cast<uint8_t>(name_len >> 8));
    sni_ext.push_back(static_cast<uint8_t>(name_len & 0xFF));
    for (char c : hostname) sni_ext.push_back(static_cast<uint8_t>(c));

    // Build extensions block
    std::vector<uint8_t> extensions;
    // SNI extension (type 0x0000)
    extensions.push_back(0x00); extensions.push_back(0x00);
    uint16_t sni_len = static_cast<uint16_t>(sni_ext.size());
    extensions.push_back(static_cast<uint8_t>(sni_len >> 8));
    extensions.push_back(static_cast<uint8_t>(sni_len & 0xFF));
    extensions.insert(extensions.end(), sni_ext.begin(), sni_ext.end());

    // Supported versions extension (type 0x002b) - TLS 1.2
    extensions.push_back(0x00); extensions.push_back(0x2b);
    extensions.push_back(0x00); extensions.push_back(0x03);  // length 3
    extensions.push_back(0x02);  // list length 2
    extensions.push_back(0x03); extensions.push_back(0x03);  // TLS 1.2

    uint16_t ext_total = static_cast<uint16_t>(extensions.size());

    // Cipher suites (common ones)
    std::vector<uint8_t> ciphers = {
        0xc0, 0x2c,  // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc0, 0x2b,  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x30,  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xc0, 0x2f,  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0x00, 0x9e,  // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        0x00, 0xff,  // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    };
    uint16_t cs_len = static_cast<uint16_t>(ciphers.size());

    // ClientHello body
    std::vector<uint8_t> hello_body;
    hello_body.push_back(0x03); hello_body.push_back(0x03);  // TLS 1.2
    // 32 bytes random (use pseudo-random but deterministic)
    for (int i = 0; i < 32; ++i) {
        hello_body.push_back(static_cast<uint8_t>((i * 17 + 31) & 0xFF));
    }
    hello_body.push_back(0x00);  // session_id length = 0
    hello_body.push_back(static_cast<uint8_t>(cs_len >> 8));
    hello_body.push_back(static_cast<uint8_t>(cs_len & 0xFF));
    hello_body.insert(hello_body.end(), ciphers.begin(), ciphers.end());
    hello_body.push_back(0x01);  // compression methods length
    hello_body.push_back(0x00);  // null compression
    hello_body.push_back(static_cast<uint8_t>(ext_total >> 8));
    hello_body.push_back(static_cast<uint8_t>(ext_total & 0xFF));
    hello_body.insert(hello_body.end(), extensions.begin(), extensions.end());

    // Handshake header
    uint32_t body_len = static_cast<uint32_t>(hello_body.size());
    std::vector<uint8_t> handshake;
    handshake.push_back(0x01);  // ClientHello
    handshake.push_back(static_cast<uint8_t>((body_len >> 16) & 0xFF));
    handshake.push_back(static_cast<uint8_t>((body_len >> 8) & 0xFF));
    handshake.push_back(static_cast<uint8_t>(body_len & 0xFF));
    handshake.insert(handshake.end(), hello_body.begin(), hello_body.end());

    // TLS record header
    uint16_t record_len = static_cast<uint16_t>(handshake.size());
    std::vector<uint8_t> record;
    record.push_back(0x16);  // Handshake
    record.push_back(0x03); record.push_back(0x01);  // TLS 1.0 (record layer)
    record.push_back(static_cast<uint8_t>(record_len >> 8));
    record.push_back(static_cast<uint8_t>(record_len & 0xFF));
    record.insert(record.end(), handshake.begin(), handshake.end());

    return record;
}

} // anonymous namespace

AutoSelector::AutoSelector() = default;

std::string AutoSelector::makeKey(const std::string& host, int port) {
    return host + ":" + std::to_string(port);
}

std::vector<TacticConfig> AutoSelector::defaultCandidates() {
    return {
        TacticConfig::tcp_split_only(3),
        TacticConfig::tcp_split_only(1),
        TacticConfig::split_and_fake(3, 1),
        TacticConfig::split_and_disorder(3),
        TacticConfig::split_and_fake(3, 2),
        TacticConfig::full(3),
    };
}

ProbeResult AutoSelector::probeSingle(const std::string& host, int port,
                                      const TacticConfig& config) {
    ProbeResult result;
    result.config = config;
    result.success = false;
    result.latency_ms = -1;

    socket_t fd = create_tcp_socket();
    if (fd == INVALID_SOCK) {
        result.error = "socket creation failed";
        return result;
    }

    auto start = std::chrono::steady_clock::now();

    int conn = connect_with_timeout(fd, host, port, probe_timeout_ms_);
    if (conn <= 0) {
        result.error = (conn == 0) ? "TCP connect timeout" : "TCP connect refused/error";
        close_socket(fd);
        return result;
    }

    auto conn_time = std::chrono::steady_clock::now();
    int conn_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(conn_time - start).count());

    set_blocking(fd);

    // Apply DPI bypass and send probe hello
    BypassSocket bypass(fd);
    bypass.setConfig(config);
    bypass.onConnected();

    auto hello = make_probe_hello(host);
    WriteResult wr = bypass.writeWithBypass(hello.data(), hello.size());

    if (!wr.success) {
        result.error = "send ClientHello failed: " + wr.error;
        close_socket(fd);
        return result;
    }

    // Wait for response with timeout
    uint8_t buf[256];
#ifdef _WIN32
    DWORD tv = static_cast<DWORD>(probe_timeout_ms_);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = probe_timeout_ms_ / 1000;
    tv.tv_usec = (probe_timeout_ms_ % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif

    int received = ::recv(fd, reinterpret_cast<char*>(buf), sizeof(buf), 0);

    auto end = std::chrono::steady_clock::now();
    result.latency_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());

    if (received > 0) {
        // Got a response — check if it's a TLS ServerHello or alert
        if (buf[0] == 0x16) {
            // TLS Handshake response (ServerHello) — success!
            result.success = true;
        } else if (buf[0] == 0x15) {
            // TLS Alert — server responded but rejected our hello
            // This still means DPI didn't block us — partial success
            result.success = true;
            result.error = "TLS alert (server rejected hello, but connection passed DPI)";
        } else {
            // Some other response
            result.success = true;
            result.error = "unexpected response type";
        }
    } else if (received == 0) {
        result.error = "connection closed by remote (possible DPI RST)";
    } else {
        // recv error
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAETIMEDOUT) {
            result.error = "recv timeout (no response in " + std::to_string(probe_timeout_ms_) + "ms)";
        } else if (err == WSAECONNRESET) {
            result.error = "connection reset (RST from DPI or server)";
        } else {
            result.error = "recv error: " + std::to_string(err);
        }
#else
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            result.error = "recv timeout (no response in " + std::to_string(probe_timeout_ms_) + "ms)";
        } else if (errno == ECONNRESET) {
            result.error = "connection reset (RST from DPI or server)";
        } else {
            result.error = "recv error: " + std::to_string(errno);
        }
#endif
    }

    close_socket(fd);
    return result;
}

void AutoSelector::probe(const std::string& host, int port,
                          const std::vector<TacticConfig>& candidates,
                          Callback on_result) {
    for (const auto& config : candidates) {
        ProbeResult result = probeSingle(host, port, config);
        if (result.success) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                cache_[makeKey(host, port)] = config;
            }
            if (on_result) {
                on_result(config);
            }
            return;
        }
    }

    // All tactics failed
    TacticConfig none;
    if (on_result) {
        on_result(none);
    }
}

std::optional<TacticConfig> AutoSelector::getCached(const std::string& host,
                                                     int port) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(makeKey(host, port));
    if (it != cache_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void AutoSelector::clearCache() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
}

bool AutoSelector::loadCache(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string key;
        uint32_t tactics_val;
        int split_pos, fake_ttl;

        if (iss >> key >> tactics_val >> split_pos >> fake_ttl) {
            TacticConfig config;
            config.tactics = static_cast<Tactic>(tactics_val);
            config.split_position = split_pos;
            config.fake_ttl = fake_ttl;
            cache_[key] = config;
        }
    }
    return true;
}

bool AutoSelector::saveCache(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ofstream file(path);
    if (!file.is_open()) return false;

    for (const auto& [key, config] : cache_) {
        file << key << " "
             << static_cast<uint32_t>(config.tactics) << " "
             << config.split_position << " "
             << config.fake_ttl << "\n";
    }
    return true;
}

} // namespace dpibypass
