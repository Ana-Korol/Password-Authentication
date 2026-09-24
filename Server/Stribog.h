#ifndef STRIBOG_H
#define STRIBOG_H

#include <vector>
#include <string>
#include <cstdint>

class Stribog
{
public:
    static const int HASH512_SIZE = 64;
    static const int HASH256_SIZE = 32;

    static std::vector<uint8_t> GetHash512(const std::vector<uint8_t>& message);
    static std::vector<uint8_t> GetHash256(const std::vector<uint8_t>& message);
    static std::string ToHexString(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> FromHexString(const std::string& hex);

private:
    static const uint8_t Pi[256];
    static const uint8_t Tau[64];
    static const uint64_t A[64];
    static const uint8_t C[12][64];

    static uint64_t BytesToU64(const uint8_t* bytes);
    static void U64ToBytes(uint8_t* bytes, uint64_t x);
    static int GetBit(uint64_t x, int i);

    static void XorVectors(uint8_t* dest, const uint8_t* a, const uint8_t* b);
    static void CopyVector(uint8_t* dest, const uint8_t* src);
    static void S(uint8_t* result, const uint8_t* a);
    static void P(uint8_t* result, const uint8_t* a);
    static void L(uint8_t* result, const uint8_t* b);
    static void LPS(uint8_t* result, const uint8_t* K, const uint8_t* input);
    static void E(uint8_t* result, const uint8_t* k, const uint8_t* m);
    static void AddMod512(uint8_t* result, const uint8_t* a, const uint8_t* b);
    static void V256(uint8_t* result, uint64_t z);
    static void G(uint8_t* result, const uint8_t* n, const uint8_t* k, const uint8_t* m);
    static void Streebog(const uint8_t* M, int nu, uint8_t* hash, bool hash256);
};

#endif // STRIBOG_H