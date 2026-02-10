cmake_minimum_required(VERSION 3.16)

add_executable(blockcheck blockcheck.cpp)
target_link_libraries(blockcheck PRIVATE dpibypass)
