#ifndef CRC32_H
#define CRC32_H

typedef unsigned int uint32;

uint32 CalcCrc32(const void* data, size_t length, uint32 priorCrc = 0);

#endif

