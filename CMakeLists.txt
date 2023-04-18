cmake_minimum_required(VERSION 3.18.1)
project(openssl-aes-gcm)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

add_library(gcm SHARED src/gcm.cpp)
add_library(thpool SHARED src/thpool.c)

add_executable(openssl-aes-gcm tests/main.cpp)

target_link_libraries(openssl-aes-gcm gcm thpool -lcrypto -lssl -pthread)
