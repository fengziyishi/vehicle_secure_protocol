#include "crypto/sm3_wrapper.h"

void SM3Hasher::hash(const std::vector<uint8_t>& input,
                   std::vector<uint8_t>& digest) {
    SM3_CTX ctx;
    uint8_t temp_digest[DIGEST_SIZE];

    sm3_init(&ctx);
    sm3_update(&ctx, input.data(), input.size());
    sm3_finish(&ctx, temp_digest);

    digest.assign(temp_digest, temp_digest + DIGEST_SIZE);
}
