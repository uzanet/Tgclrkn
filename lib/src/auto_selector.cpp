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

bool connect_with_timeout(socket_t fd, const std::string& host, int port,
                          int timeout_ms) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) {
        return false;
    }

    set_nonblocking(fd);

    int ret = ::connect(fd, res->ai_addr, static_cast<socklen_t>(res->ai_addrlen));
    freeaddrinfo(res);

    if (ret == 0) return true;

#ifdef _WIN32
    if (WSAGetLastError() != WSAEWOULDBLOCK) return false;
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ret = select(0, nullptr, &wfds, nullptr, &tv);
#else
    if (errno != EINPROGRESS) return false;
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;
    ret = poll(&pfd, 1, timeout_ms);
#endif

    if (ret <= 0) return false;

    int err = 0;
    socklen_t errlen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &errlen);
    return err == 0;
}

// Minimal TLS ClientHello to test connectivity
// This is a valid TLS 1.0 ClientHello with random data
std::vector<uint8_t> make_probe_hello() {
    // Minimal ClientHello with no extensions
    std::vector<uint8_t> hello = {
        0x16, 0x03, 0x01, 0x00, 0x2D,  // TLS record header (45 bytes payload)
        0x01, 0x00, 0x00, 0x29,          // ClientHello, length 41
        0x03, 0x01,                       // TLS 1.0
    };
    // 32 bytes random
    for (int i = 0; i < 32; ++i) {
        hello.push_back(static_cast<uint8_t>((i * 7 + 42) & 0xFF));
    }
    hello.push_back(0x00); // session_id length = 0
    hello.push_back(0x00); hello.push_back(0x02); // cipher_suites length = 2
    hello.push_back(0x00); hello.push_back(0xFF); // TLS_EMPTY_RENEGOTIATION_INFO
    hello.push_back(0x01); // compression_methods length = 1
    hello.push_back(0x00); // null compression
    return hello;
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

    socket_t fd = create_tcp_socket();
    if (fd == INVALID_SOCK) return result;

    auto start = std::chrono::steady_clock::now();

    if (!connect_with_timeout(fd, host, port, probe_timeout_ms_)) {
        close_socket(fd);
        return result;
    }

    // Set back to blocking for the probe write
#ifdef _WIN32
    unsigned long mode = 0;
    ioctlsocket(fd, FIONBIO, &mode);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
#endif

    // Apply DPI bypass and send probe hello
    BypassSocket bypass(fd);
    bypass.setConfig(config);
    bypass.onConnected();

    auto hello = make_probe_hello();
    WriteResult wr = bypass.writeWithBypass(hello.data(), hello.size());

    if (wr.success) {
        // Try to read a response (any response means the connection worked)
        uint8_t buf[256];
#ifdef _WIN32
        // Set recv timeout
        DWORD tv = static_cast<DWORD>(probe_timeout_ms_);
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
        struct timeval tv;
        tv.tv_sec = probe_timeout_ms_ / 1000;
        tv.tv_usec = (probe_timeout_ms_ % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
        int received = ::recv(fd, reinterpret_cast<char*>(buf), sizeof(buf), 0);
        if (received > 0) {
            result.success = true;
        }
    }

    auto end = std::chrono::steady_clock::now();
    result.latency_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());

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

    // All tactics failed — return None config
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

    // Simple format: key tactic_bitmask split_pos fake_ttl
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
