#include "dpibypass/socket_wrapper.h"

#ifdef __APPLE__

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <cerrno>

namespace dpibypass {
namespace platform {

bool set_tcp_nodelay(socket_t fd, bool enable) {
    int val = enable ? 1 : 0;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) == 0;
}

bool set_tcp_cork(socket_t fd, bool enable) {
    // macOS uses TCP_NOPUSH instead of TCP_CORK
    int val = enable ? 1 : 0;
    return setsockopt(fd, IPPROTO_TCP, TCP_NOPUSH, &val, sizeof(val)) == 0;
}

bool set_ttl(socket_t fd, int ttl) {
    return setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == 0;
}

int get_ttl(socket_t fd) {
    int ttl = 0;
    socklen_t len = sizeof(ttl);
    if (getsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, &len) != 0) {
        return -1;
    }
    return ttl;
}

int send_data(socket_t fd, const uint8_t* data, size_t len, int flags) {
    ssize_t result = ::send(fd, data, len, flags);
    return static_cast<int>(result);
}

int send_oob(socket_t fd, const uint8_t* data, size_t len) {
    ssize_t result = ::send(fd, data, len, MSG_OOB);
    return static_cast<int>(result);
}

} // namespace platform
} // namespace dpibypass

#endif // __APPLE__
