#include "SHA1CryptoServiceProvider.h"

void SHA1CryptoServiceProvider::InitialState(uint32_t H[], std::string &buffer, uint64_t &transforms)
{
    H[0] = 0x67452301;
    H[1] = 0xEFCDAB89;
    H[2] = 0x98BADCFE;
    H[3] = 0x10325476;
    H[4] = 0xC3D2E1F0;

    buffer = "";
    transforms = 0;
}

uint32_t SHA1CryptoServiceProvider::CircularLeftRotate(const uint32_t value, const size_t bits)
{
    return (value << bits) | (value >> (32 - bits));
}
/*
 * Process first 16 words
*/
uint32_t SHA1CryptoServiceProvider::Extend80Words(const uint32_t block[WORD16], const size_t i)
{
    return CircularLeftRotate(block[(i + 13) & 15] ^ block[(i + 8) & 15] ^ block[(i + 2) & 15] ^ block[i], 1);
}

void SHA1CryptoServiceProvider::Round0(const uint32_t block[WORD16], const uint32_t label0, uint32_t &label1, const uint32_t label2, const uint32_t label3, uint32_t &label4, const size_t index)
{
    label4 += ((label1 & (label2 ^ label3)) ^ label3) + block[index] + K[0] + CircularLeftRotate(label0, 5);
    label1 = CircularLeftRotate(label1, 30);
}

void SHA1CryptoServiceProvider::Round1(uint32_t block[WORD16], const uint32_t label0, uint32_t &label1, const uint32_t label2, const uint32_t label3, uint32_t &label4, const size_t index)
{
    block[index] = Extend80Words(block, index);
    label4 += ((label1 & (label2 ^ label3)) ^ label3) + block[index] + K[0] + CircularLeftRotate(label0, 5);
    label1 = CircularLeftRotate(label1, 30);
}

void SHA1CryptoServiceProvider::Round2(uint32_t block[WORD16], const uint32_t label0, uint32_t &label1, const uint32_t label2, const uint32_t label3, uint32_t &label4, const size_t index)
{
    block[index] = Extend80Words(block, index);
    label4 += (label1 ^ label2 ^ label3) + block[index] + K[1] + CircularLeftRotate(label0, 5);
    label1 = CircularLeftRotate(label1, 30);
}

void SHA1CryptoServiceProvider::Round3(uint32_t block[WORD16], const uint32_t label0, uint32_t &label1, const uint32_t label2, const uint32_t label3, uint32_t &label4, const size_t index)
{
    block[index] = Extend80Words(block, index);
    label4 += (((label1 | label2) & label3) | (label1&label2)) + block[index] + K[2] + CircularLeftRotate(label0, 5);
    label1 = CircularLeftRotate(label1, 30);
}

void SHA1CryptoServiceProvider::Round4(uint32_t block[WORD16], const uint32_t label0, uint32_t &label1, const uint32_t label2, const uint32_t label3, uint32_t &label4, const size_t index)
{
    block[index] = Extend80Words(block, index);
    label4 += (label1 ^ label2 ^ label3) + block[index] + K[3] + CircularLeftRotate(label0, 5);
    label1 = CircularLeftRotate(label1, 30);
}

void SHA1CryptoServiceProvider::ProcessBlock(uint32_t H[], uint32_t block[WORD16], uint64_t &transforms)
{
    uint32_t A = H[0];
    uint32_t B = H[1];
    uint32_t C = H[2];
    uint32_t D = H[3];
    uint32_t E = H[4];

    for (int i = 0; i < 15; i += 5) {
        Round0(block, A, B, C, D, E,  i);
        Round0(block, E, A, B, C, D,  i + 1);
        Round0(block, D, E, A, B, C,  i + 2);
        Round0(block, C, D, E, A, B,  i + 3);
        Round0(block, B, C, D, E, A,  i + 4);
    }

    Round0(block, A, B, C, D, E,  15);
    Round1(block, E, A, B, C, D,  0);
    Round1(block, D, E, A, B, C,  1);
    Round1(block, C, D, E, A, B,  2);
    Round1(block, B, C, D, E, A,  3);

    for (int i = 4; i < 14; i += 5) {
        Round2(block, A, B, C, D, E,  i);
        Round2(block, E, A, B, C, D,  i + 1);
        Round2(block, D, E, A, B, C,  i + 2);
        Round2(block, C, D, E, A, B,  i + 3);
        Round2(block, B, C, D, E, A,  i + 4);
    }

    Round2(block, A, B, C, D, E,  14);
    Round2(block, E, A, B, C, D,  15);
    Round2(block, D, E, A, B, C,  0);
    Round2(block, C, D, E, A, B,  1);
    Round2(block, B, C, D, E, A,  2);

    for (int i = 3; i < 13; i += 5) {
        if (i < 8)
        {
            Round2(block, A, B, C, D, E,  i);
            Round2(block, E, A, B, C, D,  i + 1);
            Round2(block, D, E, A, B, C,  i + 2);
            Round2(block, C, D, E, A, B,  i + 3);
            Round2(block, B, C, D, E, A,  i + 4);
        }
        else if(i >= 8)
        {
            Round3(block, A, B, C, D, E,  i);
            Round3(block, E, A, B, C, D,  i + 1);
            Round3(block, D, E, A, B, C,  i + 2);
            Round3(block, C, D, E, A, B,  i + 3);
            Round3(block, B, C, D, E, A,  i + 4);
        }
    }

    Round3(block, A, B, C, D, E,  13);
    Round3(block, E, A, B, C, D,  14);
    Round3(block, D, E, A, B, C,  15);
    Round3(block, C, D, E, A, B,  0);
    Round3(block, B, C, D, E, A,  1);

    for (int i = 2; i < 16; i += 5)
    {
        if (i < 12)
        {
            Round3(block, A, B, C, D, E,  i);
            Round3(block, E, A, B, C, D,  i + 1);
            Round3(block, D, E, A, B, C,  i + 2);
            Round3(block, C, D, E, A, B,  i + 3);
            Round3(block, B, C, D, E, A,  i + 4);
        }
        else if (i >= 12)
        {
            Round4(block, A, B, C, D, E,  i);
            Round4(block, E, A, B, C, D,  i + 1);
            Round4(block, D, E, A, B, C,  i + 2);
            Round4(block, C, D, E, A, B,  i + 3);
        }
    }

    Round4(block, B, C, D, E, A,  0);

    for (int i = 1; i < 16; i += 5) {
        Round4(block, A, B, C, D, E,  i);
        Round4(block, E, A, B, C, D,  i + 1);
        Round4(block, D, E, A, B, C,  i + 2);
        Round4(block, C, D, E, A, B,  i + 3);
        Round4(block, B, C, D, E, A,  i + 4);
    }

    H[0] += A;
    H[1] += B;
    H[2] += C;
    H[3] += D;
    H[4] += E;

    transforms++;
}

void SHA1CryptoServiceProvider::ToBigEndian(const std::string &inputMessage, uint32_t block[WORD16])
{
    for (size_t i = 0; i < WORD16; i++)
    {
        block[i] = (inputMessage[4 * i + 3] & 0xff)
                   | (inputMessage[4 * i + 2] & 0xff) << 8
                   | (inputMessage[4 * i + 1] & 0xff) << 16
                   | (inputMessage[4 * i + 0] & 0xff) << 24;
    }
}

inline SHA1CryptoServiceProvider::SHA1CryptoServiceProvider()
{
    InitialState(H, buffer, transforms);
}

inline void SHA1CryptoServiceProvider::Update(const std::string &inputMessage)
{
    std::istringstream is(inputMessage);

    while (true)
    {
        char interimBuffer[BLOCK_BYTES];
        is.read(interimBuffer, BLOCK_BYTES - buffer.size());
        buffer.append(interimBuffer, (std::size_t)is.gcount());
        if (buffer.size() != BLOCK_BYTES)
        {
            return;
        }
        uint32_t block[WORD16];
        ToBigEndian(buffer, block);
        ProcessBlock(H, block, transforms);
        buffer.clear();
    }
}

inline std::string SHA1CryptoServiceProvider::FinalProcess()
{
    uint64_t totalBits = (transforms * BLOCK_BYTES + buffer.size()) * 8;

    buffer += (char)0x80;
    size_t initialSize = buffer.size();
    while (buffer.size() < BLOCK_BYTES)
    {
        buffer += (char)0x00;
    }

    uint32_t block[WORD16];
    ToBigEndian(buffer, block);

    if (initialSize > BLOCK_BYTES - 8)
    {
        ProcessBlock(H, block, transforms);
        for (size_t i = 0; i < WORD16 - 2; i++)
        {
            block[i] = 0;
        }
    }

    block[WORD16 - 1] = (uint32_t)totalBits;
    block[WORD16 - 2] = (uint32_t)(totalBits >> 32);
    ProcessBlock(H, block, transforms);

    std::ostringstream result;
    for (unsigned int i : H)
    {
        result << std::hex << std::setfill('0') << std::setw(8);
        result << i;
    }

    InitialState(H, buffer, transforms);

    return result.str();
}

void SHA1CryptoServiceProvider::Hashing(const std::string& message)
{
    SHA1CryptoServiceProvider SHA1Hash;
    SHA1Hash.Update(message);
    const std::string hash = SHA1Hash.FinalProcess();
    std::cout << hash;
}
