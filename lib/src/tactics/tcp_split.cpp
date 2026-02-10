#include "tactic_base.h"
#include "dpibypass/socket_wrapper.h"

#include <algorithm>

namespace dpibypass {
namespace tactics {

WriteResult tcp_split_write(socket_t fd, const uint8_t* data, size_t len,
                            const TacticConfig& config) {
    if (len == 0) {
        return WriteResult::ok(0);
    }

    std::vector<int> positions = config.multi_split_positions;
    if (positions.empty()) {
        positions.push_back(config.split_position);
    }

    // Sort and deduplicate split positions
    std::sort(positions.begin(), positions.end());
    positions.erase(std::unique(positions.begin(), positions.end()), positions.end());

    // Remove positions outside the data range
    while (!positions.empty() && positions.back() >= static_cast<int>(len)) {
        positions.pop_back();
    }
    while (!positions.empty() && positions.front() <= 0) {
        positions.erase(positions.begin());
    }

    if (positions.empty()) {
        // No valid split positions — send as-is
        int sent = platform::send_data(fd, data, len);
        if (sent < 0) {
            return WriteResult::fail("send failed");
        }
        return WriteResult::ok(sent);
    }

    // Disable Nagle and cork to force immediate segment emission
    platform::set_tcp_nodelay(fd, true);
    platform::set_tcp_cork(fd, false);

    int total_sent = 0;
    size_t prev = 0;

    for (int pos : positions) {
        size_t chunk_len = static_cast<size_t>(pos) - prev;
        if (chunk_len > 0) {
            // Enable cork before sending to accumulate
            // Then disable to flush this segment
            int sent = platform::send_data(fd, data + prev, chunk_len);
            if (sent < 0) {
                return WriteResult::fail("send fragment failed");
            }
            total_sent += sent;
        }
        prev = static_cast<size_t>(pos);
    }

    // Send the remaining data
    if (prev < len) {
        int sent = platform::send_data(fd, data + prev, len - prev);
        if (sent < 0) {
            return WriteResult::fail("send remainder failed");
        }
        total_sent += sent;
    }

    return WriteResult::ok(total_sent);
}

} // namespace tactics
} // namespace dpibypass
