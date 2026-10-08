cmake_minimum_required(VERSION 3.15)
project(SecureProxyGateway CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(secure_proxy_gateway src/main.cpp)

target_include_directories(secure_proxy_gateway PRIVATE include)
target_compile_options(secure_proxy_gateway PRIVATE -Wall -Wextra -Wpedantic)
