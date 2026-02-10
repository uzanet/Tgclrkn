cmake_minimum_required(VERSION 3.16)

add_library(dpibypass STATIC
    src/dpibypass.cpp
    src/socket_wrapper.cpp
    src/split_positions.cpp
    src/auto_selector.cpp
    src/tactics/tcp_split.cpp
    src/tactics/fake_packet.cpp
    src/tactics/disorder.cpp
    src/tactics/oob.cpp
    src/tactics/tls_record_split.cpp
)

target_include_directories(dpibypass PUBLIC include)
target_compile_features(dpibypass PUBLIC cxx_std_17)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(dpibypass PRIVATE src/platform/linux.cpp)
    target_compile_definitions(dpibypass PRIVATE DPIBYPASS_LINUX)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_sources(dpibypass PRIVATE src/platform/windows.cpp)
    target_compile_definitions(dpibypass PRIVATE DPIBYPASS_WINDOWS)
    target_link_libraries(dpibypass PRIVATE ws2_32)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_sources(dpibypass PRIVATE src/platform/macos.cpp)
    target_compile_definitions(dpibypass PRIVATE DPIBYPASS_MACOS)
endif()

target_link_libraries(dpibypass PRIVATE pthread)
