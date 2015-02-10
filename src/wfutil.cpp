/* lzf: (C) 2011 Ian Babrou <ibobrik@gmail.com>  */
// wfutil
#include <node_version.h>
#include <node_buffer.h>
#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <string.h>

#ifdef __APPLE__
#include <malloc/malloc.h>
#endif


#include "lzf/lzf.h"
#include "crc32/crc32.h"
#include "whirlpool/whirlpool.h"


using namespace v8;
using namespace node;

typedef unsigned char uint8;
typedef unsigned short uint16;
#define ARRAY_COUNT(a)  (sizeof(a) / sizeof(a[0]))

static uint32 MakeVarIntLZF(uint32 usize, uint8 dst[5]);
static uint32 GetVarIntLZF(const uint8* src, uint32& csize);

#if NODE_MINOR_VERSION >= 12
Handle<Value> ThrowNodeError(const char* what = NULL) {
    return Isolate::GetCurrent()->ThrowException(Exception::Error(String::NewFromUtf8(v8::Isolate::GetCurrent(), what)));
}

void compress(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
        args.GetReturnValue().Set(ThrowNodeError("First argument must be a Buffer"));
        return;
    }

    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    HandleScope scope(isolate);

    Local<Object> bufferIn = args[0]->ToObject();
    size_t bytesIn         = Buffer::Length(bufferIn);
    char * dataPointer     = Buffer::Data(bufferIn);
    size_t bytesCompressed = bytesIn + 100;
    char * bufferOut        = (char*) malloc(bytesCompressed);

    unsigned result = lzf_compress(dataPointer, bytesIn, bufferOut, bytesCompressed);

    if (!result) {
        free(bufferOut);
        args.GetReturnValue().Set(Undefined(v8::Isolate::GetCurrent()));
        return;
    }

    v8::Local<v8::Object> resultBuffer = Buffer::New(isolate, bufferOut, result);
    free(bufferOut);

    args.GetReturnValue().Set(resultBuffer);
}

void decompress(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
        args.GetReturnValue().Set(ThrowNodeError("First argument must be a Buffer"));
        return;
    }

    v8::Isolate* isolate = v8::Isolate::GetCurrent();

    Local<Object> bufferIn = args[0]->ToObject();

    size_t bytesUncompressed = 999 * 1024 * 1024; // it's about max size that V8 supports

    if (args.Length() > 1 && args[1]->IsNumber()) { // accept dest buffer size
        bytesUncompressed = args[1]->Uint32Value();
    }


    char * bufferOut = (char*) malloc(bytesUncompressed);
    if (!bufferOut) {
        args.GetReturnValue().Set(ThrowNodeError("LZF malloc failed!"));
        return;
    }

    unsigned result = lzf_decompress(Buffer::Data(bufferIn), Buffer::Length(bufferIn), bufferOut, bytesUncompressed);

    if (!result) {
        args.GetReturnValue().Set(Undefined(isolate));
        return;
    }

    v8::Local<v8::Object> resultBuffer = Buffer::New(isolate, bufferOut, result);

    free(bufferOut);

    args.GetReturnValue().Set(resultBuffer);
}

void crc32(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
        args.GetReturnValue().Set(ThrowNodeError("First argument must be a Buffer"));
        return;
    }

    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    HandleScope scope(isolate);

    Local<Object> bufferIn = args[0]->ToObject();
    size_t bytesIn         = Buffer::Length(bufferIn);
    char * dataPointer     = Buffer::Data(bufferIn);

    uint32 prior = 0;
    if (args.Length() > 1 && args[1]->IsNumber()) {
        prior = args[1]->Uint32Value();
        unsigned char* f = (unsigned char*)&prior;
        prior = f[3] | (f[2] << 8) | (f[1] << 16) | (f[0] << 24);
    }

    uint32 result = CalcCrc32(dataPointer, bytesIn, prior);
    unsigned char* f = (unsigned char*)&result;
    result = f[3] | (f[2] << 8) | (f[1] << 16) | (f[0] << 24);

    args.GetReturnValue().Set(Number::New(isolate, result));
}

void whirlpool(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
        args.GetReturnValue().Set(ThrowNodeError("First argument must be a Buffer"));
        return;
    }

    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    Local<Object> bufferIn = args[0]->ToObject();

    Whirlpool wp;
    WhirlpoolHash wh;

    wp.Hash(Buffer::Data(bufferIn), Buffer::Length(bufferIn));
    wp.Get(wh);

    v8::Local<v8::Object> resultBuffer = Buffer::New(isolate, (const char*)&wh.bytes[0], 64);
    args.GetReturnValue().Set(resultBuffer);
}

void verifyPacket(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 3 || !Buffer::HasInstance(args[0]) || !Buffer::HasInstance(args[1]) || !Buffer::HasInstance(args[2])) {
        args.GetReturnValue().Set(ThrowNodeError("First argument must be a Buffer"));
        return;
    }

    //std::cout << "verifyPacket: " << "\n";
    v8::Isolate* isolate = v8::Isolate::GetCurrent();

    Local<Object> bufferIn = args[0]->ToObject();
    Local<Object> saltBuffer = args[1]->ToObject();
    Local<Object> destBuffer = args[2]->ToObject();

    size_t bytesIn              = Buffer::Length(bufferIn);
    uint8* dataPointer        = (uint8*)Buffer::Data(bufferIn);
    uint8* destDataPointer  = (uint8*)Buffer::Data(destBuffer);
    size_t destBytesSize     = Buffer::Length(destBuffer);

    if(bytesIn < 5) { // illegal size need at least varint byte & packet hash
        args.GetReturnValue().Set(Undefined(isolate));
        return;
    }

    uint32 csize = bytesIn;
    uint32 uncompressedSize = GetVarIntLZF(dataPointer, csize);
    
    uint8 packetBuffer[16384] = { 0 }; // static packet decomp buffer.
    if(uncompressedSize > ARRAY_COUNT(packetBuffer)) {
        args.GetReturnValue().Set(Undefined(isolate));
        return;
    }

    // strip varint heading
    if(uncompressedSize == 0)
    {
        dataPointer++;
        bytesIn--;
    }
    else
    {
        uint32 offset = static_cast<uint32>(bytesIn) - csize;
        dataPointer += offset;
        //std::cout << "Decompressing: " << uncompressedSize << " csize " << csize << "\n";
        uint32 result = lzf_decompress(dataPointer, csize, packetBuffer, uncompressedSize);
        if (!result) {
            args.GetReturnValue().Set(Undefined(isolate));
            return;
        }
        bytesIn = uncompressedSize;
        dataPointer = &packetBuffer[0];
    }

    //std::cout << "bytesIn: " << bytesIn << " csize " << csize << "\n";

    // saw off packet hash
    uint32 expectedHash = *(uint32*)dataPointer;
    dataPointer += 4; bytesIn -= 4;
    
    //std::cout << "expectedHash: " << std::hex << expectedHash << "\n";

    // calc hash of packet data plus salt
    uint32 crc = CalcCrc32(dataPointer, bytesIn, 0);
    crc =  CalcCrc32(Buffer::Data(saltBuffer), Buffer::Length(saltBuffer), crc); // add in salt.
    crc = (crc & 0x000000FFU) << 24 | (crc & 0x0000FF00U) << 8 | (crc & 0x00FF0000U) >> 8 | (crc & 0xFF000000U) >> 24;

    //std::cout << "crc: " << std::hex << crc << "\n";

    if(expectedHash != crc || destBytesSize < bytesIn) {
        //std::cout << "hashFail!\n";
        args.GetReturnValue().Set(Undefined(isolate));
        return;
    }

    //std::cout << "return new buffer: " << bytesIn << "\n";

    //Buffer* BufferOut = Buffer::New((char*)dataPointer, bytesIn);
    memcpy(destDataPointer, dataPointer, bytesIn);
    
    args.GetReturnValue().Set(Number::New(isolate, bytesIn));
}

void conditionPacket(const FunctionCallbackInfo<Value>& args) {
    if (args.Length() < 3 || !Buffer::HasInstance(args[0]) || !Buffer::HasInstance(args[1]) || !Buffer::HasInstance(args[2])) {
        args.GetReturnValue().Set(ThrowNodeError("First 3 arguments must be a Buffers"));
        return;
    }
    
    v8::Isolate* isolate = v8::Isolate::GetCurrent();

    Local<Object> bufferIn = args[0]->ToObject();
    Local<Object> saltBuffer = args[1]->ToObject();
    Local<Object> destBuffer = args[2]->ToObject();

    char* bytes = Buffer::Data(bufferIn);
    uint32 len = Buffer::Length(bufferIn);
    
    uint8* packetBuffer  = (uint8*)Buffer::Data(destBuffer);
    size_t destBytesSize     = Buffer::Length(destBuffer);
    
    const size_t HEADER_SIZE = 1 + 4 + 2 + 2 + 2;
    
    if (len > 1400 || (len + HEADER_SIZE) > destBytesSize) {
        // MTU explosions
        args.GetReturnValue().Set(Undefined(isolate));
        return;
    }
    
    // !! lots of endian assumptions here.
    uint8* outBytes = packetBuffer;
    
    // compression header 1 byte compression header = 0 = no compression
    *outBytes = 0; outBytes++;

    // hash header recall this position for hash
    uint32* crcPtr = (uint32*)outBytes; outBytes += 4; 
    
    uint8* hashStart = outBytes;

    // connectionless header
    *(uint16*)outBytes = 0; outBytes += 2; // 16 bit packet num
    *(uint16*)outBytes = (2 << 14); outBytes += 2; // 16 but chunk header
    *(uint16*)outBytes = len; outBytes += 2; // packet size

    // append payload data
    memcpy(outBytes, bytes, len);
    outBytes += len;

    ptrdiff_t totalBufferSize = (ptrdiff_t)outBytes - (ptrdiff_t)packetBuffer;

    // calc hash
    uint32 crc = CalcCrc32(packetBuffer + 5, totalBufferSize - 5, 0);
    crc =  CalcCrc32(Buffer::Data(saltBuffer), Buffer::Length(saltBuffer), crc); // add in salt.
    *crcPtr = (crc & 0x000000FFU) << 24 | (crc & 0x0000FF00U) << 8 | (crc & 0x00FF0000U) >> 8 | (crc & 0xFF000000U) >> 24;
    
    //std::cout << "crc: " << std::hex << *crcPtr << " " << totalBufferSize << "\n";

    //Buffer* BufferOut = Buffer::New(packetBuffer, totalBufferSize);
    //HandleScope scope;
    //return scope.Close(BufferOut->handle_);
    args.GetReturnValue().Set(Number::New(isolate, totalBufferSize));
}

#else // Node v10

Handle<Value> ThrowNodeError(const char* what = NULL) {
    return ThrowException(Exception::Error(String::New(what)));
}

Handle<Value> compress(const Arguments& args) {
    if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
        return ThrowNodeError("First argument must be a Buffer");
    }

    HandleScope scope;

    Local<Object> bufferIn = args[0]->ToObject();
    size_t bytesIn         = Buffer::Length(bufferIn);
    char * dataPointer     = Buffer::Data(bufferIn);
    size_t bytesCompressed = bytesIn + 100;
    char * bufferOut        = (char*) malloc(bytesCompressed);

    unsigned result = lzf_compress(dataPointer, bytesIn, bufferOut, bytesCompressed);

    if (!result) {
        free(bufferOut);
        return Undefined();
    }

    Buffer *BufferOut = Buffer::New(bufferOut, result);
    free(bufferOut);

    return scope.Close(BufferOut->handle_);
}

Handle<Value> decompress(const Arguments &args) {
    if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
        return ThrowNodeError("First argument must be a Buffer");
    }

    Local<Object> bufferIn = args[0]->ToObject();

    size_t bytesUncompressed = 999 * 1024 * 1024; // it's about max size that V8 supports

    if (args.Length() > 1 && args[1]->IsNumber()) { // accept dest buffer size
        bytesUncompressed = args[1]->Uint32Value();
    }


    char * bufferOut = (char*) malloc(bytesUncompressed);
    if (!bufferOut) {
        return ThrowNodeError("LZF malloc failed!");
    }

    unsigned result = lzf_decompress(Buffer::Data(bufferIn), Buffer::Length(bufferIn), bufferOut, bytesUncompressed);

    if (!result) {
        return Undefined();
    }

    Buffer * BufferOut = Buffer::New(bufferOut, result);

    free(bufferOut);

    HandleScope scope;
    return scope.Close(BufferOut->handle_);
}

Handle<Value> crc32(const Arguments& args) {
    if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
        return ThrowNodeError("First argument must be a Buffer");
    }

    HandleScope scope;

    Local<Object> bufferIn = args[0]->ToObject();
    size_t bytesIn         = Buffer::Length(bufferIn);
    char * dataPointer     = Buffer::Data(bufferIn);

    uint32 prior = 0;
    if (args.Length() > 1 && args[1]->IsNumber()) {
        prior = args[1]->Uint32Value();
        unsigned char* f = (unsigned char*)&prior;
        prior = f[3] | (f[2] << 8) | (f[1] << 16) | (f[0] << 24);
    }

    uint32 result = CalcCrc32(dataPointer, bytesIn, prior);
    unsigned char* f = (unsigned char*)&result;
    result = f[3] | (f[2] << 8) | (f[1] << 16) | (f[0] << 24);

    return scope.Close(Number::New(result));
}

Handle<Value> whirlpool(const Arguments& args) {
    if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
        return ThrowNodeError("First argument must be a Buffer");
    }

    Local<Object> bufferIn = args[0]->ToObject();

    Whirlpool wp;
    WhirlpoolHash wh;

    wp.Hash(Buffer::Data(bufferIn), Buffer::Length(bufferIn));
    wp.Get(wh);

    Buffer* BufferOut = Buffer::New((const char*)&wh.bytes[0], 64);

    HandleScope scope;
    return scope.Close(BufferOut->handle_);
}

Handle<Value> verifyPacket(const Arguments &args) {
    if (args.Length() < 3 || !Buffer::HasInstance(args[0]) || !Buffer::HasInstance(args[1]) || !Buffer::HasInstance(args[2])) {
        return ThrowNodeError("First 3 arguments must be Buffers");
    }

    //std::cout << "verifyPacket: " << "\n";

    Local<Object> bufferIn = args[0]->ToObject();
    Local<Object> saltBuffer = args[1]->ToObject();
    Local<Object> destBuffer = args[2]->ToObject();

    size_t bytesIn              = Buffer::Length(bufferIn);
    uint8* dataPointer        = (uint8*)Buffer::Data(bufferIn);
    uint8* destDataPointer  = (uint8*)Buffer::Data(destBuffer);
    size_t destBytesSize     = Buffer::Length(destBuffer);

    if(bytesIn < 5) { // illegal size need at least varint byte & packet hash
        return Undefined();
    }

    uint32 csize = bytesIn;
    uint32 uncompressedSize = GetVarIntLZF(dataPointer, csize);
    
    uint8 packetBuffer[16384] = { 0 }; // static packet decomp buffer.
    if(uncompressedSize > ARRAY_COUNT(packetBuffer)) {
        return Undefined();    
    }

    // strip varint heading
    if(uncompressedSize == 0)
    {
        dataPointer++;
        bytesIn--;
    }
    else
    {
        uint32 offset = static_cast<uint32>(bytesIn) - csize;
        dataPointer += offset;
        //std::cout << "Decompressing: " << uncompressedSize << " csize " << csize << "\n";
        uint32 result = lzf_decompress(dataPointer, csize, packetBuffer, uncompressedSize);
        if (!result) {
            return Undefined();
        }
        bytesIn = uncompressedSize;
        dataPointer = &packetBuffer[0];
    }

    //std::cout << "bytesIn: " << bytesIn << " csize " << csize << "\n";

    // saw off packet hash
    uint32 expectedHash = *(uint32*)dataPointer;
    dataPointer += 4; bytesIn -= 4;
    
    //std::cout << "expectedHash: " << std::hex << expectedHash << "\n";

    // calc hash of packet data plus salt
    uint32 crc = CalcCrc32(dataPointer, bytesIn, 0);
    crc =  CalcCrc32(Buffer::Data(saltBuffer), Buffer::Length(saltBuffer), crc); // add in salt.
    crc = (crc & 0x000000FFU) << 24 | (crc & 0x0000FF00U) << 8 | (crc & 0x00FF0000U) >> 8 | (crc & 0xFF000000U) >> 24;

    //std::cout << "crc: " << std::hex << crc << "\n";

    if(expectedHash != crc || destBytesSize < bytesIn) {
        //std::cout << "hashFail!\n";
        return Undefined();
    }

    //std::cout << "return new buffer: " << bytesIn << "\n";

    //Buffer* BufferOut = Buffer::New((char*)dataPointer, bytesIn);
    memcpy(destDataPointer, dataPointer, bytesIn);
    
    
    HandleScope scope;
    return scope.Close(Number::New(bytesIn));
}

Handle<Value> conditionPacket(const Arguments &args) {
    if (args.Length() < 3 || !Buffer::HasInstance(args[0]) || !Buffer::HasInstance(args[1]) || !Buffer::HasInstance(args[2])) {
        return ThrowNodeError("First 3 arguments must be Buffers");
    }
    
    Local<Object> bufferIn = args[0]->ToObject();
    Local<Object> saltBuffer = args[1]->ToObject();
    Local<Object> destBuffer = args[2]->ToObject();

    char* bytes = Buffer::Data(bufferIn);
    uint32 len = Buffer::Length(bufferIn);
    
    uint8* packetBuffer  = (uint8*)Buffer::Data(destBuffer);
    size_t destBytesSize     = Buffer::Length(destBuffer);
    
    const size_t HEADER_SIZE = 1 + 4 + 2 + 2 + 2;
    
    if (len > 1400 || (len + HEADER_SIZE) > destBytesSize) {
        // MTU explosions
        return Undefined();
    }
    
    // !! lots of endian assumptions here.
    uint8* outBytes = packetBuffer;
    
    // compression header 1 byte compression header = 0 = no compression
    *outBytes = 0; outBytes++;

    // hash header recall this position for hash
    uint32* crcPtr = (uint32*)outBytes; outBytes += 4; 
    
    uint8* hashStart = outBytes;

    // connectionless header
    *(uint16*)outBytes = 0; outBytes += 2; // 16 bit packet num
    *(uint16*)outBytes = (2 << 14); outBytes += 2; // 16 but chunk header
    *(uint16*)outBytes = len; outBytes += 2; // packet size

    // append payload data
    memcpy(outBytes, bytes, len);
    outBytes += len;

    ptrdiff_t totalBufferSize = (ptrdiff_t)outBytes - (ptrdiff_t)packetBuffer;

    // calc hash
    uint32 crc = CalcCrc32(packetBuffer + 5, totalBufferSize - 5, 0);
    crc =  CalcCrc32(Buffer::Data(saltBuffer), Buffer::Length(saltBuffer), crc); // add in salt.
    *crcPtr = (crc & 0x000000FFU) << 24 | (crc & 0x0000FF00U) << 8 | (crc & 0x00FF0000U) >> 8 | (crc & 0xFF000000U) >> 24;
    
    //std::cout << "crc: " << std::hex << *crcPtr << " " << totalBufferSize << "\n";

    //Buffer* BufferOut = Buffer::New(packetBuffer, totalBufferSize);
    //HandleScope scope;
    //return scope.Close(BufferOut->handle_);
    HandleScope scope;
    return scope.Close(Number::New(totalBufferSize));
}
#endif

// varint size encoding needed for perl's LZF compression
// NOTE: I am matching the LZF version but it is wrong for for large packet sizes (e.g. usize <= 0x7fffffff is wrong, varint of 0xffffffff fits in 5 bytes!)

inline static uint8 TruncateByte(uint32 b)
{
    return(static_cast<uint8>(b & 0xff));
}

static uint32 MakeVarIntLZF(uint32 usize, uint8 dst[5])
{
    uint32 skip = 0;

    if(usize <= 0x7f)
    {
        dst[skip++] = TruncateByte(usize);
    }
    else if(usize <= 0x7ff) 
    {
        dst[skip++] = TruncateByte(( usize >>  6)         | 0xc0);
        dst[skip++] = TruncateByte(( usize        & 0x3f) | 0x80);
    }
    else if(usize <= 0xffff) 
    {
        dst[skip++] = TruncateByte(( usize >> 12)         | 0xe0);
        dst[skip++] = TruncateByte(((usize >>  6) & 0x3f) | 0x80);
        dst[skip++] = TruncateByte(( usize        & 0x3f) | 0x80);
    }
    else if(usize <= 0x1fffff) 
    {
        dst[skip++] = TruncateByte(( usize >> 18)         | 0xf0);
        dst[skip++] = TruncateByte(((usize >> 12) & 0x3f) | 0x80);
        dst[skip++] = TruncateByte(((usize >>  6) & 0x3f) | 0x80);
        dst[skip++] = TruncateByte(( usize        & 0x3f) | 0x80);
    }
    else if(usize <= 0x3ffffff) 
    {
        dst[skip++] = TruncateByte(( usize >> 24)         | 0xf8);
        dst[skip++] = TruncateByte(((usize >> 18) & 0x3f) | 0x80);
        dst[skip++] = TruncateByte(((usize >> 12) & 0x3f) | 0x80);
        dst[skip++] = TruncateByte(((usize >>  6) & 0x3f) | 0x80);
        dst[skip++] = TruncateByte(( usize        & 0x3f) | 0x80);
    }
    else if(usize <= 0x7fffffff) 
    {
        dst[skip++] = TruncateByte(( usize >> 30)         | 0xfc);
        dst[skip++] = TruncateByte(((usize >> 24) & 0x3f) | 0x80);
        dst[skip++] = TruncateByte(((usize >> 18) & 0x3f) | 0x80);
        dst[skip++] = TruncateByte(((usize >> 12) & 0x3f) | 0x80);
        dst[skip++] = TruncateByte(((usize >>  6) & 0x3f) | 0x80);
        dst[skip++] = TruncateByte(( usize        & 0x3f) | 0x80);
    }
    return(skip);
}

static uint32 GetVarIntLZF(const uint8* src, uint32& csize)
{
    uint32 usize = 0;
    
    // check for zero = no compression
    if(!src[0])
    {
        usize = csize - 1;
        return(0);
    }

    // compressed, decomp the buffer with csize offset
    if (!(src[0] & 0x80) && csize >= 1)
    {
        csize -= 1;
        usize =                 *src++ & 0xff;
    }
    else if (!(src[0] & 0x20) && csize >= 2)
    {
        csize -= 2;
        usize =                 *src++ & 0x1f;
        usize = (usize << 6) | (*src++ & 0x3f);
    }
    else if (!(src[0] & 0x10) && csize >= 3)
    {
        csize -= 3;
        usize =                 *src++ & 0x0f;
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
    }
    else if (!(src[0] & 0x08) && csize >= 4)
    {
        csize -= 4;
        usize =                 *src++ & 0x07;
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
    }
    else if (!(src[0] & 0x04) && csize >= 5)
    {
        csize -= 5;
        usize =                 *src++ & 0x03;
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
    }
    else if (!(src[0] & 0x02) && csize >= 6)
    {
        csize -= 6;
        usize =                 *src++ & 0x01;
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
    }
    return(usize);
}

extern "C" void
    init (Handle<Object> target) {
        NODE_SET_METHOD(target, "compress", compress);
        NODE_SET_METHOD(target, "decompress", decompress);
        NODE_SET_METHOD(target, "crc32", crc32);
        NODE_SET_METHOD(target, "whirlpool", whirlpool);
        NODE_SET_METHOD(target, "verifyPacket", verifyPacket);
        NODE_SET_METHOD(target, "conditionPacket", conditionPacket);
}

NODE_MODULE(wfutil, init);
