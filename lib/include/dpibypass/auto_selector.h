#pragma once

#include "dpibypass/tactics.h"

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <functional>
#include <mutex>

namespace dpibypass {

struct ProbeResult {
    TacticConfig config;
    bool success = false;
    int latency_ms = 0;
    std::string error;
};

class AutoSelector {
public:
    using Callback = std::function<void(TacticConfig best)>;

    AutoSelector();
    ~AutoSelector() = default;

    void probe(const std::string& host, int port,
               const std::vector<TacticConfig>& candidates,
               Callback on_result);

    std::optional<TacticConfig> getCached(const std::string& host, int port) const;

    void clearCache();

    bool loadCache(const std::string& path);
    bool saveCache(const std::string& path) const;

    static std::vector<TacticConfig> defaultCandidates();

    void setProbeTimeout(int ms) { probe_timeout_ms_ = ms; }

    ProbeResult probeSingle(const std::string& host, int port,
                            const TacticConfig& config);

private:
    static std::string makeKey(const std::string& host, int port);

    mutable std::mutex mutex_;
    std::map<std::string, TacticConfig> cache_;
    int probe_timeout_ms_ = 5000;
};

} // namespace dpibypass
