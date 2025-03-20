#pragma once
#include <vector>
#include <stdexcept>
#include <gmssl/sm2.h>

class SM2Wrapper {
public:
    static const size_t PUBLIC_KEY_SIZE = 65;   // 未压缩公钥格式: 04 + x + y (64字节)
    static const size_t PRIVATE_KEY_SIZE = 32;
    static const size_t SIGNATURE_SIZE = 64;
    static const size_t SHARED_KEY_SIZE = 32;
    static const size_t HKDF_MAX_SIZE = 1024;
    // 生成SM2密钥对
    static void generate_key_pair(std::vector<uint8_t>& public_key, 
                                 std::vector<uint8_t>& private_key);
                                
    // 生成临时SM2密钥对（前向安全）
    static void generate_ephemeral_key(std::vector<uint8_t>& public_key,
                                std::vector<uint8_t>& private_key) {
                                generate_key_pair(public_key, private_key); // 相同实现但语义不同
                                }
    // 使用SM2私钥签名数据
    static bool sign(const std::vector<uint8_t>& private_key,
                    const std::vector<uint8_t>& message,
                    std::vector<uint8_t>& signature);

    // 使用SM2公钥验证签名
    static bool verify(const std::vector<uint8_t>& public_key,
                     const std::vector<uint8_t>& message,
                     const std::vector<uint8_t>& signature);

    // ECDH密钥协商
    static bool ecdh(const std::vector<uint8_t>& private_key,
                   const std::vector<uint8_t>& peer_public_key,
                   std::vector<uint8_t>& shared_key);

private:
    static void handle_gmssl_error(const char* func_name, int ret);
};
