#pragma once

#include <cstddef>
#include <cstdint>

#ifdef _WIN32
#include <winsock2.h>
using socket_t = SOCKET;
constexpr socket_t INVALID_SOCK = INVALID_SOCKET;
#else
using socket_t = int;
constexpr socket_t INVALID_SOCK = -1;
#endif

namespace dpibypass {
namespace platform {

bool set_tcp_nodelay(socket_t fd, bool enable);
bool set_tcp_cork(socket_t fd, bool enable);
bool set_ttl(socket_t fd, int ttl);
int get_ttl(socket_t fd);
int send_data(socket_t fd, const uint8_t* data, size_t len, int flags = 0);
int send_oob(socket_t fd, const uint8_t* data, size_t len);

} // namespace platform
} // namespace dpibypass
