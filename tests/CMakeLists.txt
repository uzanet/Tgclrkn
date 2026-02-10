cmake_minimum_required(VERSION 3.16)

# Simple test framework using assert
# For production, consider GoogleTest or Catch2

add_executable(test_tcp_split test_tcp_split.cpp)
target_link_libraries(test_tcp_split PRIVATE dpibypass)
add_test(NAME tcp_split COMMAND test_tcp_split)

add_executable(test_disorder test_disorder.cpp)
target_link_libraries(test_disorder PRIVATE dpibypass)
add_test(NAME disorder COMMAND test_disorder)

add_executable(test_fake_packet test_fake_packet.cpp)
target_link_libraries(test_fake_packet PRIVATE dpibypass)
add_test(NAME fake_packet COMMAND test_fake_packet)

add_executable(test_auto_selector test_auto_selector.cpp)
target_link_libraries(test_auto_selector PRIVATE dpibypass)
add_test(NAME auto_selector COMMAND test_auto_selector)

add_executable(test_integration test_integration.cpp)
target_link_libraries(test_integration PRIVATE dpibypass)
add_test(NAME integration COMMAND test_integration)
