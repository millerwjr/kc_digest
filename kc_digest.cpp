//
// Copyright 2017 Wyatt Miller
//
// THIS CODE BORROWS SIGNIFICANTLY FROM:
// MD5 -
// http://www.zedwood.com/article/cpp-md5-function
// https://bobobobo.wordpress.com/2010/10/17/md5-c-implementation/
//
// SHA1 -
// http://www.zedwood.com/article/cpp-sha1-function
//
// SHA256 -
// http://www.zedwood.com/article/cpp-sha256-function
//
// Please attribute accordingly.



#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include "kc_digest.h"



////////// DIGEST //////////

std::string kc::digest::md5(std::string const &text) const {
    kc::md5 mymd5;
    return mymd5.hash(text);
}



std::string kc::digest::md5(std::ifstream const &infile) const {
    kc::md5 mymd5;
    return mymd5.hash(infile);
}



std::string kc::digest::sha1(std::string const &text) const {
    kc::sha1 mysha1;
    return mysha1.hash(text);
}



std::string kc::digest::sha1(std::ifstream const &infile) const {
    kc::sha1 mysha1;
    return mysha1.hash(infile);
}



std::string kc::digest::sha256(std::string const &text) const {
    kc::sha256 mysha256;
    return mysha256.hash(text);
}



std::string kc::digest::sha256(std::ifstream const &infile) const {
    kc::sha256 mysha256;
    return mysha256.hash(infile);
}



////////// MD5    //////////

// F, G, H and I are basic MD5 functions.
inline kc::md5::uint4 kc::md5::F(uint4 x, uint4 y, uint4 z) {
    return x&y | ~x&z;
}



inline kc::md5::uint4 kc::md5::G(uint4 x, uint4 y, uint4 z) {
    return x&z | y&~z;
}



inline kc::md5::uint4 kc::md5::H(uint4 x, uint4 y, uint4 z) {
    return x^y^z;
}



inline kc::md5::uint4 kc::md5::I(uint4 x, uint4 y, uint4 z) {
    return y ^ (x | ~z);
}



// rotate_left rotates x left n bits.
inline kc::md5::uint4 kc::md5::rotate_left(uint4 x, int n) {
    return (x << n) | (x >> (32-n));
}



// FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
// Rotation is separate from addition to prevent recomputation.
inline void kc::md5::FF(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
    a = rotate_left(a+ F(b,c,d) + x + ac, s) + b;
}



inline void kc::md5::GG(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
    a = rotate_left(a + G(b,c,d) + x + ac, s) + b;
}



inline void kc::md5::HH(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
    a = rotate_left(a + H(b,c,d) + x + ac, s) + b;
}



inline void kc::md5::II(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
    a = rotate_left(a + I(b,c,d) + x + ac, s) + b;
}



kc::md5::md5()
{
    // init
    finalized=false;
    count[0] = 0;
    count[1] = 0;
    // load magic initialization constants.
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;
}



kc::md5::md5(const std::string &text) {

    // Init
    finalized = false;
    count[0] = 0;
    count[1] = 0;
    // Load magic initialization constants.
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;

    update(text.c_str(), text.length());

    // MD5 finalization. Ends an MD5 message-digest operation, writing the
    // the message digest and zeroizing the context.
    static unsigned char padding[64] = {
            0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    if (!finalized) {
        // Save number of bits
        unsigned char bits[8];
        encode(bits, count, 8);

        // pad out to 56 mod 64.
        size_type index = count[0] / 8 % 64;
        size_type padLen = (index < 56) ? (56 - index) : (120 - index);
        update(padding, padLen);

        // Append length (before padding)
        update(bits, 8);

        // Store state in digest
        encode(digest, state, 16);

        // Zeroize sensitive information.
        memset(buffer, 0, sizeof buffer);
        memset(count, 0, sizeof count);

        finalized = true;
    }
}



std::string kc::md5::hash(const std::string &text) const {
    kc::md5 md5_wrapper = kc::md5(text);
    return md5_wrapper.hexdigest();
}



std::string kc::md5::hash(const std::ifstream &infile) const {
    std::stringstream ss;
    ss << infile.rdbuf();
    kc::md5 md5_wrapper = kc::md5(ss.str());
    return md5_wrapper.hexdigest();
}



// decodes input (unsigned char) into output (uint4). Assumes len is a multiple of 4.
void kc::md5::decode(uint4 output[], const uint1 input[], size_type len)
{
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4)
        output[i] = ((uint4)input[j]) | (((uint4)input[j+1]) << 8) | (((uint4)input[j+2]) << 16) | (((uint4)input[j+3]) << 24);
}



// encodes input (uint4) into output (unsigned char). Assumes len is
// a multiple of 4.
void kc::md5::encode(uint1 output[], const uint4 input[], size_type len)
{
    for (size_type i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = input[i] & 0xff;
        output[j+1] = (input[i] >> 8) & 0xff;
        output[j+2] = (input[i] >> 16) & 0xff;
        output[j+3] = (input[i] >> 24) & 0xff;
    }
}



// apply MD5 algo on a block
void kc::md5::transform(const uint1 block[blocksize])
{
    uint4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    decode (x, block, blocksize);

    /* Round 1 */
    FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
    FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
    FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
    FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
    FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
    FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
    FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
    FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
    FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
    FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
    FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
    FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
    FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
    FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
    FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
    FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

    /* Round 2 */
    GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
    GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
    GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
    GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
    GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
    GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
    GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
    GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
    GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
    GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
    GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
    GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
    GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
    GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
    GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
    GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
    HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
    HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
    HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
    HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
    HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
    HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
    HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
    HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
    HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
    HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
    HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
    HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
    HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
    HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
    HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

    /* Round 4 */
    II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
    II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
    II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
    II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
    II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
    II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
    II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
    II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
    II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
    II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
    II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
    II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
    II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
    II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
    II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
    II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    // Zeroize sensitive information.
    memset(x, 0, sizeof x);
}



// MD5 block update operation. Continues an MD5 message-digest
// operation, processing another message block
void kc::md5::update(const unsigned char input[], size_type length)
{
    // compute number of bytes mod 64
    size_type index = count[0] / 8 % blocksize;

    // Update number of bits
    if ((count[0] += (length << 3)) < (length << 3))
        count[1]++;
    count[1] += (length >> 29);

    // number of bytes we need to fill in buffer
    size_type firstpart = 64 - index;

    size_type i;

    // transform as many times as possible.
    if (length >= firstpart)
    {
        // fill buffer first, transform
        memcpy(&buffer[index], input, firstpart);
        transform(buffer);

        // transform chunks of blocksize (64 bytes)
        for (i = firstpart; i + blocksize <= length; i += blocksize)
            transform(&input[i]);

        index = 0;
    }
    else
        i = 0;

    // buffer remaining input
    memcpy(&buffer[index], &input[i], length-i);
}



// for convenience provide a verson with signed char
void kc::md5::update(const char input[], size_type length)
{
    update((const unsigned char*)input, length);
}



// return hex representation of digest as string
std::string kc::md5::hexdigest() const
{
    if (!finalized)
        return "";

    char buf[33];
    for (int i=0; i<16; i++)
        sprintf(buf+i*2, "%02x", digest[i]);
    buf[32]=0;

    return std::string(buf);
}



/* MD5
 converted to C++ class by Frank Thilo (thilo@unix-ag.org)
 for bzflag (http://www.bzflag.org)

   based on:

   md5.h and md5.c
   reference implementation of RFC 1321

   Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.

*/



////////// SHA1   //////////

kc::sha1::sha1()
{
    reset();
}


void kc::sha1::update(const std::string &s)
{
    std::istringstream is(s);
    update(is);
}


void kc::sha1::update(std::istream &is)
{
    std::string rest_of_buffer;
    read(is, rest_of_buffer, BLOCK_BYTES - buffer.size());
    buffer += rest_of_buffer;

    while (is)
    {
        uint32 block[BLOCK_INTS];
        buffer_to_block(buffer, block);
        transform(block);
        read(is, buffer, BLOCK_BYTES);
    }
}


/*
 * Add padding and return the message digest.
 */

std::string kc::sha1::final()
{
    /* Total number of hashed bits */
    uint64 total_bits = (transforms*BLOCK_BYTES + buffer.size()) * 8;

    /* Padding */
    buffer += 0x80;
    unsigned int orig_size = buffer.size();
    while (buffer.size() < BLOCK_BYTES)
    {
        buffer += (char)0x00;
    }

    uint32 block[BLOCK_INTS];
    buffer_to_block(buffer, block);

    if (orig_size > BLOCK_BYTES - 8)
    {
        transform(block);
        for (unsigned int i = 0; i < BLOCK_INTS - 2; i++)
        {
            block[i] = 0;
        }
    }

    /* Append total_bits, split this uint64 into two uint32 */
    block[BLOCK_INTS - 1] = total_bits;
    block[BLOCK_INTS - 2] = (total_bits >> 32);
    transform(block);

    /* Hex std::string */
    std::ostringstream result;
    for (unsigned int i = 0; i < DIGEST_INTS; i++)
    {
        result << std::hex << std::setfill('0') << std::setw(8);
        result << (digest[i] & 0xffffffff);
    }

    /* Reset for next run */
    reset();

    return result.str();
}


std::string kc::sha1::from_file(const std::string &filename)
{
    std::ifstream stream(filename.c_str(), std::ios::binary);
    kc::sha1 checksum;
    checksum.update(stream);
    return checksum.final();
}


void kc::sha1::reset()
{
    /* SHA1 initialization constants */
    digest[0] = 0x67452301;
    digest[1] = 0xefcdab89;
    digest[2] = 0x98badcfe;
    digest[3] = 0x10325476;
    digest[4] = 0xc3d2e1f0;

    /* Reset counters */
    transforms = 0;
    buffer = "";
}


/*
 * Hash a single 512-bit block. This is the core of the algorithm.
 */

void kc::sha1::transform(uint32 block[BLOCK_BYTES])
{
    /* Copy digest[] to working vars */
    uint32 a = digest[0];
    uint32 b = digest[1];
    uint32 c = digest[2];
    uint32 d = digest[3];
    uint32 e = digest[4];


    /* 4 rounds of 20 operations each. Loop unrolled. */
    SHA1_R0(a,b,c,d,e, 0);
    SHA1_R0(e,a,b,c,d, 1);
    SHA1_R0(d,e,a,b,c, 2);
    SHA1_R0(c,d,e,a,b, 3);
    SHA1_R0(b,c,d,e,a, 4);
    SHA1_R0(a,b,c,d,e, 5);
    SHA1_R0(e,a,b,c,d, 6);
    SHA1_R0(d,e,a,b,c, 7);
    SHA1_R0(c,d,e,a,b, 8);
    SHA1_R0(b,c,d,e,a, 9);
    SHA1_R0(a,b,c,d,e,10);
    SHA1_R0(e,a,b,c,d,11);
    SHA1_R0(d,e,a,b,c,12);
    SHA1_R0(c,d,e,a,b,13);
    SHA1_R0(b,c,d,e,a,14);
    SHA1_R0(a,b,c,d,e,15);
    SHA1_R1(e,a,b,c,d,16);
    SHA1_R1(d,e,a,b,c,17);
    SHA1_R1(c,d,e,a,b,18);
    SHA1_R1(b,c,d,e,a,19);
    SHA1_R2(a,b,c,d,e,20);
    SHA1_R2(e,a,b,c,d,21);
    SHA1_R2(d,e,a,b,c,22);
    SHA1_R2(c,d,e,a,b,23);
    SHA1_R2(b,c,d,e,a,24);
    SHA1_R2(a,b,c,d,e,25);
    SHA1_R2(e,a,b,c,d,26);
    SHA1_R2(d,e,a,b,c,27);
    SHA1_R2(c,d,e,a,b,28);
    SHA1_R2(b,c,d,e,a,29);
    SHA1_R2(a,b,c,d,e,30);
    SHA1_R2(e,a,b,c,d,31);
    SHA1_R2(d,e,a,b,c,32);
    SHA1_R2(c,d,e,a,b,33);
    SHA1_R2(b,c,d,e,a,34);
    SHA1_R2(a,b,c,d,e,35);
    SHA1_R2(e,a,b,c,d,36);
    SHA1_R2(d,e,a,b,c,37);
    SHA1_R2(c,d,e,a,b,38);
    SHA1_R2(b,c,d,e,a,39);
    SHA1_R3(a,b,c,d,e,40);
    SHA1_R3(e,a,b,c,d,41);
    SHA1_R3(d,e,a,b,c,42);
    SHA1_R3(c,d,e,a,b,43);
    SHA1_R3(b,c,d,e,a,44);
    SHA1_R3(a,b,c,d,e,45);
    SHA1_R3(e,a,b,c,d,46);
    SHA1_R3(d,e,a,b,c,47);
    SHA1_R3(c,d,e,a,b,48);
    SHA1_R3(b,c,d,e,a,49);
    SHA1_R3(a,b,c,d,e,50);
    SHA1_R3(e,a,b,c,d,51);
    SHA1_R3(d,e,a,b,c,52);
    SHA1_R3(c,d,e,a,b,53);
    SHA1_R3(b,c,d,e,a,54);
    SHA1_R3(a,b,c,d,e,55);
    SHA1_R3(e,a,b,c,d,56);
    SHA1_R3(d,e,a,b,c,57);
    SHA1_R3(c,d,e,a,b,58);
    SHA1_R3(b,c,d,e,a,59);
    SHA1_R4(a,b,c,d,e,60);
    SHA1_R4(e,a,b,c,d,61);
    SHA1_R4(d,e,a,b,c,62);
    SHA1_R4(c,d,e,a,b,63);
    SHA1_R4(b,c,d,e,a,64);
    SHA1_R4(a,b,c,d,e,65);
    SHA1_R4(e,a,b,c,d,66);
    SHA1_R4(d,e,a,b,c,67);
    SHA1_R4(c,d,e,a,b,68);
    SHA1_R4(b,c,d,e,a,69);
    SHA1_R4(a,b,c,d,e,70);
    SHA1_R4(e,a,b,c,d,71);
    SHA1_R4(d,e,a,b,c,72);
    SHA1_R4(c,d,e,a,b,73);
    SHA1_R4(b,c,d,e,a,74);
    SHA1_R4(a,b,c,d,e,75);
    SHA1_R4(e,a,b,c,d,76);
    SHA1_R4(d,e,a,b,c,77);
    SHA1_R4(c,d,e,a,b,78);
    SHA1_R4(b,c,d,e,a,79);

    /* Add the working vars back into digest[] */
    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;
    digest[4] += e;

    /* Count the number of transformations */
    transforms++;
}


void kc::sha1::buffer_to_block(const std::string &buffer, uint32 block[BLOCK_BYTES])
{
    /* Convert the std::string (byte buffer) to a uint32 array (MSB) */
    for (unsigned int i = 0; i < BLOCK_INTS; i++)
    {
        block[i] = (buffer[4*i+3] & 0xff)
                   | (buffer[4*i+2] & 0xff)<<8
                   | (buffer[4*i+1] & 0xff)<<16
                   | (buffer[4*i+0] & 0xff)<<24;
    }
}


void kc::sha1::read(std::istream &is, std::string &s, int max)
{
    char sbuf[max];
    is.read(sbuf, max);
    s.assign(sbuf, is.gcount());
}


std::string kc::sha1::hash(const std::string &string) const
{
    kc::sha1 sha1_wrapper;
    sha1_wrapper.update(string);
    return sha1_wrapper.final();
}


std::string kc::sha1::hash(const std::ifstream &infile) const
{
    std::stringstream ss;
    ss << infile.rdbuf();
    kc::sha1 checksum;
    checksum.update(ss.str());
    return checksum.final();
}



////////// SHA256 //////////
const unsigned int kc::sha256::sha256_k[64] = //UL = uint32
        {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
         0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
         0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
         0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
         0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
         0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
         0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
         0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
         0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};



void kc::sha256::transform(const unsigned char *message, unsigned int block_nb)
{
    uint32 w[64];
    uint32 wv[8];
    uint32 t1, t2;
    const unsigned char *sub_block;
    int i;
    int j;
    for (i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 6);
        for (j = 0; j < 16; j++) {
            SHA2_PACK32(&sub_block[j << 2], &w[j]);
        }
        for (j = 16; j < 64; j++) {
            w[j] =  SHA256_F4(w[j -  2]) + w[j -  7] + SHA256_F3(w[j - 15]) + w[j - 16];
        }
        for (j = 0; j < 8; j++) {
            wv[j] = m_h[j];
        }
        for (j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
                 + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }
        for (j = 0; j < 8; j++) {
            m_h[j] += wv[j];
        }
    }
}



void kc::sha256::init()
{
    m_h[0] = 0x6a09e667;
    m_h[1] = 0xbb67ae85;
    m_h[2] = 0x3c6ef372;
    m_h[3] = 0xa54ff53a;
    m_h[4] = 0x510e527f;
    m_h[5] = 0x9b05688c;
    m_h[6] = 0x1f83d9ab;
    m_h[7] = 0x5be0cd19;
    m_len = 0;
    m_tot_len = 0;
}



void kc::sha256::update(const unsigned char *message, unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;
    tmp_len = SHA224_256_BLOCK_SIZE - m_len;
    rem_len = len < tmp_len ? len : tmp_len;
    memcpy(&m_block[m_len], message, rem_len);
    if (m_len + len < SHA224_256_BLOCK_SIZE) {
        m_len += len;
        return;
    }
    new_len = len - rem_len;
    block_nb = new_len / SHA224_256_BLOCK_SIZE;
    shifted_message = message + rem_len;
    transform(m_block, 1);
    transform(shifted_message, block_nb);
    rem_len = new_len % SHA224_256_BLOCK_SIZE;
    memcpy(m_block, &shifted_message[block_nb << 6], rem_len);
    m_len = rem_len;
    m_tot_len += (block_nb + 1) << 6;
}



void kc::sha256::final(unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;
    int i;
    block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9) < (m_len % SHA224_256_BLOCK_SIZE)));
    len_b = (m_tot_len + m_len) << 3;
    pm_len = block_nb << 6;
    memset(m_block + m_len, 0, pm_len - m_len);
    m_block[m_len] = 0x80;
    SHA2_UNPACK32(len_b, m_block + pm_len - 4);
    transform(m_block, block_nb);
    for (i = 0 ; i < 8; i++) {
        SHA2_UNPACK32(m_h[i], &digest[i << 2]);
    }
}



std::string kc::sha256::hash(std::string const &text) const {
    unsigned char digest[sha256::DIGEST_SIZE];
    memset(digest, 0, sha256::DIGEST_SIZE);

    sha256 ctx = sha256();
    ctx.init();
    ctx.update((unsigned char *) text.c_str(), text.length());
    ctx.final(digest);

    char buf[2 * sha256::DIGEST_SIZE + 1];
    buf[2 * sha256::DIGEST_SIZE] = 0;
    for (int i = 0; i < sha256::DIGEST_SIZE; i++)
        sprintf(buf + i * 2, "%02x", digest[i]);
    return std::string(buf);
}



std::string kc::sha256::hash(std::ifstream const &infile) const {
    std::stringstream ss;
    ss << infile.rdbuf();
    return this->hash(ss.str());
}



/*
 * Proxy Licensing Information
 * Updated to C++, zedwood.com 2012
 * Based on Olivier Gay's version
 * See Modified BSD License below:
 *
 * FIPS 180-2 SHA-224/256/384/512 implementation
 * Issue date:  04/30/2005
 * http://www.ouah.org/ogay/sha2/
 *
 * Copyright (C) 2005, 2007 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */




