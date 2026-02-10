#include "tactic_base.h"
#include "dpibypass/socket_wrapper.h"

#include <algorithm>

namespace dpibypass {
namespace tactics {

WriteResult disorder_write(socket_t fd, const uint8_t* data, size_t len,
                           const TacticConfig& config) {
    // Disorder (desync) strategy:
    //
    // Split data at split_position into [segment1] [segment2]
    //
    // 1. Set TTL=1, send segment1 (will be dropped by network, but DPI sees it)
    // 2. Restore TTL, send segment2 (reaches server)
    // 3. Send segment1 again with normal TTL (TCP retransmit — reaches server)
    //
    // The DPI sees: segment1 then segment2 (in order, but segment1 is incomplete/garbage)
    // The server sees: segment2 then segment1 (out of order, reassembled by TCP stack)
    //
    // This confuses stateful DPI that expects data in TCP sequence order.

    int split_pos = config.split_position;
    if (split_pos <= 0 || static_cast<size_t>(split_pos) >= len) {
        // Can't split — send normally
        int sent = platform::send_data(fd, data, len);
        if (sent < 0) return WriteResult::fail("disorder: send failed");
        return WriteResult::ok(sent);
    }

    int orig_ttl = platform::get_ttl(fd);
    if (orig_ttl <= 0) {
        orig_ttl = 64;
    }

    const uint8_t* seg1 = data;
    size_t seg1_len = static_cast<size_t>(split_pos);
    const uint8_t* seg2 = data + split_pos;
    size_t seg2_len = len - seg1_len;

    // Force immediate segment emission
    platform::set_tcp_nodelay(fd, true);
    platform::set_tcp_cork(fd, false);

    // Step 1: Send segment1 with low TTL (will be dropped, DPI sees it)
    platform::set_ttl(fd, config.disorder_ttl);
    platform::send_data(fd, seg1, seg1_len);
    // Don't check return — the packet is expected to be dropped

    // Step 2: Restore TTL, send segment2 (real data, reaches server)
    platform::set_ttl(fd, orig_ttl);
    int sent2 = platform::send_data(fd, seg2, seg2_len);
    if (sent2 < 0) {
        return WriteResult::fail("disorder: send segment2 failed");
    }

    // Step 3: The kernel's TCP retransmission will resend segment1
    // after the retransmit timeout (RTO). Alternatively, we can
    // explicitly resend it:
    int sent1 = platform::send_data(fd, seg1, seg1_len);
    if (sent1 < 0) {
        return WriteResult::fail("disorder: resend segment1 failed");
    }

    return WriteResult::ok(static_cast<int>(len));
}

} // namespace tactics
} // namespace dpibypass
