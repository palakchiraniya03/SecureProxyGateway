#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include <string>
#include <string_view>
#include <cstdint>
#include <cstddef>
#include <optional>

enum class ParseStatus {
    Success,
    Incomplete,
    Error
};

struct HttpRequest {
    ParseStatus status{ParseStatus::Incomplete};
    std::string method;
    std::string request_target;
    std::string version;
    std::string host_header;
    std::string host;
    uint16_t port{80};
    std::string path{"/"};
    std::string proxy_authorization;
    std::optional<size_t> content_length;
    size_t header_length{0}; // Byte offset where the header block ends
    bool valid{false};
    std::string error_message;

    bool is_complete() const { return status == ParseStatus::Success; }
    bool is_incomplete() const { return status == ParseStatus::Incomplete; }
    bool is_error() const { return status == ParseStatus::Error; }
};

class HttpParser {
public:
    static constexpr size_t MAX_HEADER_BLOCK_SIZE = 8192; // 8 KB

    static HttpRequest parse(std::string_view raw_request);
    static std::string make_400_response();
    static std::string sanitize_path(std::string_view path);
};

#endif // HTTP_PARSER_H
