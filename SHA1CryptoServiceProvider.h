#ifndef SHA1_SHA1CRYPTOSERVICEPROVIDER_H
#define SHA1_SHA1CRYPTOSERVICEPROVIDER_H


#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

static const size_t WORD16 = 16;
static const size_t BLOCK_BYTES = WORD16 * 4;

class SHA1CryptoServiceProvider
{
public:
    SHA1CryptoServiceProvider();
    static void Hashing(const std::string& message);
private:
    uint32_t H[5]{};
    uint32_t K[4] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };
    std::string buffer;
    uint64_t transforms{};

    static void InitialState(uint32_t H[], std::string &buffer, uint64_t &transforms);
    void Update(const std::string &inputMessage);
    static void ToBigEndian(const std::string &inputMessage, uint32_t block[WORD16]);
    static uint32_t CircularLeftRotate(uint32_t value, size_t bits);
    static uint32_t Extend80Words(const uint32_t block[WORD16], size_t i);
    void Round0(const uint32_t block[WORD16], uint32_t label0, uint32_t &label1, uint32_t label2, uint32_t label3, uint32_t &label4, size_t index);
    void Round1(uint32_t block[WORD16], uint32_t label0, uint32_t &label1, uint32_t label2, uint32_t label3, uint32_t &label4, size_t index);
    void Round2(uint32_t block[WORD16], uint32_t label0, uint32_t &label1, uint32_t label2, uint32_t label3, uint32_t &label4, size_t index);
    void Round3(uint32_t block[WORD16], uint32_t label0, uint32_t &label1, uint32_t label2, uint32_t label3, uint32_t &label4, size_t index);
    void Round4(uint32_t block[WORD16], uint32_t label0, uint32_t &label1, uint32_t label2, uint32_t label3, uint32_t &label4, size_t index);
    void ProcessBlock(uint32_t H[], uint32_t block[WORD16], uint64_t &transforms);
    std::string FinalProcess();

};

#endif //SHA1_SHA1CRYPTOSERVICEPROVIDER_H
