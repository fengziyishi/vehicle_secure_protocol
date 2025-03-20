#pragma once
#include <vector>
#include <stdexcept>
#include <gmssl/sm3.h>

class SM3Hasher {
public:
    static const size_t DIGEST_SIZE = 32;

    static void hash(const std::vector<uint8_t>& input,
                   std::vector<uint8_t>& digest);
};
