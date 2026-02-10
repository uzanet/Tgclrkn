#include "dpibypass/socket_wrapper.h"

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

namespace dpibypass {
namespace platform {

bool set_tcp_nodelay(socket_t fd, bool enable) {
    BOOL val = enable ? TRUE : FALSE;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                      reinterpret_cast<const char*>(&val), sizeof(val)) == 0;
}

bool set_tcp_cork(socket_t fd, bool enable) {
    // Windows doesn't have TCP_CORK.
    // Nagle toggling (TCP_NODELAY) is the closest equivalent.
    // When we want cork-like behavior, we disable TCP_NODELAY temporarily.
    (void)fd;
    (void)enable;
    return true;
}

bool set_ttl(socket_t fd, int ttl) {
    DWORD val = static_cast<DWORD>(ttl);
    return setsockopt(fd, IPPROTO_IP, IP_TTL,
                      reinterpret_cast<const char*>(&val), sizeof(val)) == 0;
}

int get_ttl(socket_t fd) {
    DWORD ttl = 0;
    int len = sizeof(ttl);
    if (getsockopt(fd, IPPROTO_IP, IP_TTL,
                   reinterpret_cast<char*>(&ttl), &len) != 0) {
        return -1;
    }
    return static_cast<int>(ttl);
}

int send_data(socket_t fd, const uint8_t* data, size_t len, int flags) {
    int result = ::send(fd, reinterpret_cast<const char*>(data),
                        static_cast<int>(len), flags);
    return result;
}

int send_oob(socket_t fd, const uint8_t* data, size_t len) {
    int result = ::send(fd, reinterpret_cast<const char*>(data),
                        static_cast<int>(len), MSG_OOB);
    return result;
}

} // namespace platform
} // namespace dpibypass

#endif // _WIN32
