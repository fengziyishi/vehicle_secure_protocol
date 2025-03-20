#include "crypto/sm4_wrapper.h"

void SM4Cipher::check_key_iv(const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& iv) {
    if (key.size() != KEY_SIZE)
        throw std::invalid_argument("Invalid SM4 key size");
    if (iv.size() != IV_SIZE)
        throw std::invalid_argument("Invalid SM4 IV size");
}

void SM4Cipher::ctr_crypt(const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& iv,
                        const std::vector<uint8_t>& input,
                        std::vector<uint8_t>& output) {
    check_key_iv(key, iv);

    SM4_CTR_CTX ctx;
    uint8_t ivec[IV_SIZE];
    memcpy(ivec, iv.data(), IV_SIZE);

    int ret = sm4_ctr_encrypt_init(&ctx, key.data(), ivec);
    if (ret != 1)
        throw std::runtime_error("SM4 CTR init failed");

    output.resize(input.size());
    size_t outlen;

    ret = sm4_ctr_encrypt_update(&ctx, input.data(), input.size(), 
                               output.data(), &outlen);
    if (ret != 1)
        throw std::runtime_error("SM4 CTR update failed");

    ret = sm4_ctr_encrypt_finish(&ctx, output.data() + outlen, &outlen);
    if (ret != 1)
        throw std::runtime_error("SM4 CTR finish failed");
}
