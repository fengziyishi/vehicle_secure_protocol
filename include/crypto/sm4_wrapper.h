#pragma once
#include <vector>
#include <stdexcept>
#include <gmssl/sm4.h>

class SM4Cipher {
public:
    static const size_t BLOCK_SIZE = 16;
    static const size_t KEY_SIZE = 16;
    static const size_t IV_SIZE = 16;

    // CTR模式加密（加密解密使用相同函数）
    static void ctr_crypt(const std::vector<uint8_t>& key,
                         const std::vector<uint8_t>& iv,
                         const std::vector<uint8_t>& input,
                         std::vector<uint8_t>& output);

private:
    static void check_key_iv(const std::vector<uint8_t>& key,
                            const std::vector<uint8_t>& iv);
};
