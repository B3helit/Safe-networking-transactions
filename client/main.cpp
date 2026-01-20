// client.cpp
#include <iostream>
#include <ctime>
#include "httplib.h"       // cpp-httplib single header
#include "json.hpp"        // nlohmann::json single header
#include "hmac_utils.h"    // from above

using json = nlohmann::json;

int main() {
    const std::string server_host = "127.0.0.1";
    const int server_port = 8000;

    const std::string user_id = "user123";
    // Must match Python server's USERS["user123"]["shared_key"]
    const std::string shared_key = "THIS_IS_A_32_BYTE_MINIMUM_SECRET_KEY";

    // Build request
    long long timestamp = static_cast<long long>(std::time(nullptr));
    std::string path = "/check_status";

    // Canonical message to sign
    std::string canonical = user_id + "|" + std::to_string(timestamp) + "|" + path;
    std::string tag_hex = hmac_sha512_hex(shared_key, canonical);

    json payload;
    payload["user_id"] = user_id;
    payload["timestamp"] = timestamp;
    payload["tag"] = tag_hex;

    httplib::Client cli(server_host, server_port);
    cli.set_connection_timeout(5); // seconds

    auto res = cli.Post(path.c_str(), payload.dump(), "application/json");
    if (!res) {
        std::cerr << "Request failed: " << res.error() << std::endl;
        return 1;
    }

    if (res->status != 200) {
        std::cerr << "Server returned status " << res->status
            << ": " << res->body << std::endl;
        return 1;
    }

    json resp;
    try {
        resp = json::parse(res->body);
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to parse JSON: " << e.what() << std::endl;
        return 1;
    }

    // Extract fields
    std::string resp_user_id = resp.value("user_id", "");
    bool resp_active = resp.value("active", false);
    std::string resp_expires = resp.value("expires_at", "");
    long long resp_server_time = resp.value("server_time", 0LL);
    std::string resp_tag = resp.value("tag", "");

    if (resp_user_id != user_id) {
        std::cerr << "Mismatching user_id in response!" << std::endl;
        return 1;
    }

    int active_int = resp_active ? 1 : 0;
    std::string resp_path = "/check_status_response";
    std::string canonical_resp = resp_user_id + "|" +
        std::to_string(active_int) + "|" +
        resp_expires + "|" +
        std::to_string(resp_server_time) + "|" +
        resp_path;


    std::cout << "Response tag: " << canonical_resp << "\n";
    std::string expected_resp_tag = hmac_sha512_hex(shared_key, canonical_resp);

    if (!constant_time_equal(expected_resp_tag, resp_tag)) {
        std::cerr << "Invalid HMAC on response! Data may be tampered." << std::endl;
        return 1;
    }

    // If we reach here, integrity + auth is good.
    std::cout << "Server HMAC OK.\n";
    std::cout << "Active: " << (resp_active ? "YES" : "NO") << "\n";
    std::cout << "Expires at (server): " << resp_expires << "\n";
    std::cout << "Server time: " << resp_server_time << "\n";

    return 0;
}
