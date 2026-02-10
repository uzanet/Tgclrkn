#pragma once

#include "dpibypass/tactics.h"
#include "dpibypass/socket_wrapper.h"
#include "dpibypass/dpibypass.h"

#include <vector>

namespace dpibypass {
namespace tactics {

WriteResult tcp_split_write(socket_t fd, const uint8_t* data, size_t len,
                            const TacticConfig& config);

WriteResult fake_rst_write(socket_t fd, const uint8_t* data, size_t len,
                           const TacticConfig& config);

WriteResult fake_data_write(socket_t fd, const uint8_t* data, size_t len,
                            const TacticConfig& config);

WriteResult disorder_write(socket_t fd, const uint8_t* data, size_t len,
                           const TacticConfig& config);

WriteResult oob_write(socket_t fd, const uint8_t* data, size_t len,
                      const TacticConfig& config);

WriteResult tls_record_split_write(socket_t fd, const uint8_t* data, size_t len,
                                   const TacticConfig& config);

std::vector<int> calculate_split_positions(const uint8_t* data, size_t len,
                                           Protocol proto,
                                           const TacticConfig& config);

} // namespace tactics
} // namespace dpibypass
