#include "dpibypass/auto_selector.h"
#include "dpibypass/tactics.h"

#include <cassert>
#include <cstdio>
#include <filesystem>

using namespace dpibypass;

void test_default_candidates() {
    printf("test_default_candidates... ");

    auto candidates = AutoSelector::defaultCandidates();
    assert(!candidates.empty());
    assert(candidates.size() >= 4);

    // First candidate should be simple TCP split
    assert(has_tactic(candidates[0].tactics, Tactic::TcpSplit));

    printf("OK\n");
}

void test_cache_operations() {
    printf("test_cache_operations... ");

    AutoSelector selector;

    // No cache initially
    auto result = selector.getCached("149.154.167.50", 443);
    assert(!result.has_value());

    // Save/load cache
    std::string cache_path = "/tmp/dpibypass_test_cache.txt";

    // Create a cache entry manually by probing localhost (which won't succeed
    // but we can test the caching mechanism)
    selector.clearCache();

    // Test save empty cache
    assert(selector.saveCache(cache_path));

    // Test load empty cache
    AutoSelector selector2;
    assert(selector2.loadCache(cache_path));

    // Cleanup
    std::filesystem::remove(cache_path);

    printf("OK\n");
}

void test_tactic_config_presets() {
    printf("test_tactic_config_presets... ");

    auto split = TacticConfig::tcp_split_only(5);
    assert(has_tactic(split.tactics, Tactic::TcpSplit));
    assert(!has_tactic(split.tactics, Tactic::FakeRst));
    assert(split.split_position == 5);

    auto split_fake = TacticConfig::split_and_fake(3, 2);
    assert(has_tactic(split_fake.tactics, Tactic::TcpSplit));
    assert(has_tactic(split_fake.tactics, Tactic::FakeRst));
    assert(split_fake.fake_ttl == 2);

    auto split_disorder = TacticConfig::split_and_disorder(10);
    assert(has_tactic(split_disorder.tactics, Tactic::TcpSplit));
    assert(has_tactic(split_disorder.tactics, Tactic::Disorder));
    assert(split_disorder.split_position == 10);

    auto full = TacticConfig::full(3);
    assert(has_tactic(full.tactics, Tactic::TcpSplit));
    assert(has_tactic(full.tactics, Tactic::FakeData));
    assert(has_tactic(full.tactics, Tactic::OOB));

    printf("OK\n");
}

int main() {
    printf("=== AutoSelector Tests ===\n");
    test_default_candidates();
    test_cache_operations();
    test_tactic_config_presets();
    printf("All auto selector tests passed!\n");
    return 0;
}
