#include "crypto/sm2_wrapper.h"
#include <cstring>

void SM2Wrapper::handle_gmssl_error(const char* func_name, int ret) {
    throw std::runtime_error(std::string(func_name) + 
                            " failed with error code: " + 
                            std::to_string(ret));
}

void SM2Wrapper::generate_key_pair(std::vector<uint8_t>& public_key,
                                  std::vector<uint8_t>& private_key) {
    SM2_KEY key;
    int ret = sm2_key_generate(&key);
    if (ret != 1) handle_gmssl_error("sm2_key_generate", ret);

    public_key.resize(PUBLIC_KEY_SIZE);
    private_key.resize(PRIVATE_KEY_SIZE);
    
    uint8_t temp_public_key[PUBLIC_KEY_SIZE];
    memcpy(temp_public_key, key.public_key.X, 32); // 假设 x 坐标是 32 字节
    memcpy(temp_public_key + 32, key.public_key.Y, 32); // 假设 y 坐标是 32 字节

    memcpy(public_key.data(), temp_public_key, PUBLIC_KEY_SIZE);
    memcpy(private_key.data(), key.private_key, PRIVATE_KEY_SIZE);
}

bool SM2Wrapper::sign(const std::vector<uint8_t>& private_key,
                     const std::vector<uint8_t>& message,
                     std::vector<uint8_t>& signature) {
    SM2_KEY key;
    SM2_SIGN_CTX ctx;
    uint8_t sig[72];
    size_t siglen;

    if (private_key.size() != PRIVATE_KEY_SIZE)
        return false;

    memcpy(key.private_key, private_key.data(), PRIVATE_KEY_SIZE);
    
    int ret = sm2_sign_init(&ctx, &key,SM2_DEFAULT_ID,strlen(SM2_DEFAULT_ID));
    if (ret != 1) return false;

    ret = sm2_sign_update(&ctx, message.data(), message.size());
    if (ret != 1) return false;

    ret = sm2_sign_finish(&ctx, sig, &siglen);
    if (ret != 1 || siglen != 64) return false;

    signature.assign(sig, sig + siglen);
    return true;
}

bool SM2Wrapper::verify(const std::vector<uint8_t>& public_key,
                      const std::vector<uint8_t>& message,
                      const std::vector<uint8_t>& signature) {
    SM2_KEY key;
    SM2_VERIFY_CTX ctx;

    if (public_key.size() != PUBLIC_KEY_SIZE || 
        signature.size() != SIGNATURE_SIZE)
        return false;

    uint8_t temp_public_key[PUBLIC_KEY_SIZE];

        // 假设 key.public_key 是一个包含 x 和 y 坐标的结构体
        // 并且 x 和 y 都是 uint8_t 数组
    std::memcpy(temp_public_key, key.public_key.X, 32); 
    std::memcpy(temp_public_key + 32, key.public_key.Y, 32); 
    memcpy(temp_public_key, public_key.data(), PUBLIC_KEY_SIZE);

    int ret = sm2_verify_init(&ctx, &key,SM2_DEFAULT_ID,strlen(SM2_DEFAULT_ID));
    if (ret != 1) return false;

    ret = sm2_verify_update(&ctx, message.data(), message.size());
    if (ret != 1) return false;

    ret = sm2_verify_finish(&ctx, signature.data(), signature.size());
    return ret == 1;
}

bool SM2Wrapper::ecdh(const std::vector<uint8_t>& private_key,
                    const std::vector<uint8_t>& peer_public_key,
                    std::vector<uint8_t>& shared_key) {
    SM2_KEY self_key;
    uint8_t temp_shared[32];

    if (private_key.size() != PRIVATE_KEY_SIZE ||
        peer_public_key.size() != PUBLIC_KEY_SIZE)
        return false;

    memcpy(self_key.private_key, private_key.data(), PRIVATE_KEY_SIZE);

    int ret = sm2_ecdh(&self_key, peer_public_key.data(), sizeof(temp_shared), temp_shared);
    if (ret != 1) return false;

    shared_key.assign(temp_shared, temp_shared + SHARED_KEY_SIZE);
    return true;
}
