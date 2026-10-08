cmake_minimum_required(VERSION 3.15)
project(SecureProxyGateway CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Main executable
add_executable(secure_proxy_gateway
    src/main.cpp
    src/http_parser.cpp
)
target_include_directories(secure_proxy_gateway PRIVATE include)
target_compile_options(secure_proxy_gateway PRIVATE -Wall -Wextra -Wpedantic)

# Unit tests
enable_testing()
add_executable(test_http_parser
    tests/test_http_parser.cpp
    src/http_parser.cpp
)
target_include_directories(test_http_parser PRIVATE include)
target_compile_options(test_http_parser PRIVATE -Wall -Wextra -Wpedantic)

add_test(NAME HttpParserTest COMMAND test_http_parser)
