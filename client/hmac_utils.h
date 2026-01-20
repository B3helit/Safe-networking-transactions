// hmac_utils.h
#pragma once
//#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <iomanip>

inline std::string to_hex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    return oss.str();
}

inline std::string hmac_sha512_hex(const std::string& key,
    const std::string& message) {
    unsigned int len = 0;
    unsigned char mac[EVP_MAX_MD_SIZE];

    if (!HMAC(EVP_sha512(),
        key.data(), static_cast<int>(key.size()),
        reinterpret_cast<const unsigned char*>(message.data()),
        static_cast<int>(message.size()),
        mac, &len)) {
        throw std::runtime_error("HMAC failed");
    }

    return to_hex(mac, len);
}

// constant-time compare words
inline bool constant_time_equal(const std::string& a,
    const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}
