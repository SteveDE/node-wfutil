#ifndef WHIRLPOOL_H
#define WHIRLPOOL_H

typedef unsigned char uint8;
typedef unsigned long long uint64;

// To hash something, make a Whirlpool object, call Hash with your data as many times as
// you like and then call Get to retrieve the MD5 hash value. Note that since the
// algorithm is a block algorithm it will pad your data when you call "Get" to
// complete the last block so multiple calls to "Get" are not recommended.
struct WhirlpoolHash
{
    WhirlpoolHash();

    bool IsZero() const;

    bool operator==(const WhirlpoolHash& other) const;
    bool operator!=(const WhirlpoolHash& other) const;

    uint8 bytes[64];
};

class Whirlpool
{
public:
    Whirlpool();
    
    void Hash(const void* input, size_t size);
    void Get(WhirlpoolHash& hash);

private:
    // IE: NESSIEstruct
	uint8  bitLength[32];
	uint8  buffer[64];
	int bufferBits;
	int bufferPos;
	uint64 hash[8];
};

#endif
