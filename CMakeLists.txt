cmake_minimum_required(VERSION 3.18.1)
project(openssl-aes-gcm)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(${PROJECT_NAME} src/gcm.cpp)
add_executable(${PROJECT_NAME} src/thpool.c)
add_executable(${PROJECT_NAME} tests/main.cpp)

target_link_libraries(${PROJECT_NAME} -lcrypto -lssl -pthread)
