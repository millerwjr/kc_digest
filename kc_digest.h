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

#ifndef KC_DIGEST_H
#define KC_DIGEST_H



#include <string>
#include <fstream>



////////// GLOBALS - MD5    //////////

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21



////////// GLOBALS - SHA1   //////////

#define SHA1_ROL(value, bits) (((value) << (bits)) | (((value) & 0xffffffff) >> (32 - (bits))))
#define SHA1_BLK(i) (block[i&15] = SHA1_ROL(block[(i+13)&15] ^ block[(i+8)&15] ^ block[(i+2)&15] ^ block[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define SHA1_R0(v,w,x,y,z,i) z += ((w&(x^y))^y)     + block[i]    + 0x5a827999 + SHA1_ROL(v,5); w=SHA1_ROL(w,30);
#define SHA1_R1(v,w,x,y,z,i) z += ((w&(x^y))^y)     + SHA1_BLK(i) + 0x5a827999 + SHA1_ROL(v,5); w=SHA1_ROL(w,30);
#define SHA1_R2(v,w,x,y,z,i) z += (w^x^y)           + SHA1_BLK(i) + 0x6ed9eba1 + SHA1_ROL(v,5); w=SHA1_ROL(w,30);
#define SHA1_R3(v,w,x,y,z,i) z += (((w|x)&y)|(w&x)) + SHA1_BLK(i) + 0x8f1bbcdc + SHA1_ROL(v,5); w=SHA1_ROL(w,30);
#define SHA1_R4(v,w,x,y,z,i) z += (w^x^y)           + SHA1_BLK(i) + 0xca62c1d6 + SHA1_ROL(v,5); w=SHA1_ROL(w,30);



////////// GLOBALS - SHA256 //////////

#define SHA2_SHFR(x, n)    (x >> n)
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_F1(x) (SHA2_ROTR(x,  2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
#define SHA256_F2(x) (SHA2_ROTR(x,  6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
#define SHA256_F3(x) (SHA2_ROTR(x,  7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x,  3))
#define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))
#define SHA2_UNPACK32(x, str)                 \
{                                             \
    *((str) + 3) = (uint8) ((x)      );       \
    *((str) + 2) = (uint8) ((x) >>  8);       \
    *((str) + 1) = (uint8) ((x) >> 16);       \
    *((str) + 0) = (uint8) ((x) >> 24);       \
}
#define SHA2_PACK32(str, x)                   \
{                                             \
    *(x) =   ((uint32) *((str) + 3)      )    \
           | ((uint32) *((str) + 2) <<  8)    \
           | ((uint32) *((str) + 1) << 16)    \
           | ((uint32) *((str) + 0) << 24);   \
}



////////// kc::digest //////////

namespace kc {

    class digest {

    public:
        std::string md5(std::string const &text) const;
        std::string md5(std::ifstream const &infile) const;
        std::string sha1(std::string const &text) const;
        std::string sha1(std::ifstream const &infile) const;
        std::string sha256(std::string const &text) const;
        std::string sha256(std::ifstream const &infile) const;
    };



    class md5
    {
    public:

        md5();
        std::string hash(const std::string &text) const;
        std::string hash(const std::ifstream &infile) const;

    private:
        typedef unsigned int size_type; // must be 32bit
        typedef unsigned char uint1; //  8bit
        typedef unsigned int uint4;  // 32bit
        enum {blocksize = 64}; // VC6 won't eat a const static int here

        md5(const std::string& text);
        void update(const unsigned char *buf, size_type length);
        void update(const char *buf, size_type length);

        std::string hexdigest() const;
        void transform(const uint1 block[blocksize]);
        static void decode(uint4 output[], const uint1 input[], size_type len);
        static void encode(uint1 output[], const uint4 input[], size_type len);

        bool finalized;
        uint1 buffer[blocksize]; // bytes that didn't fit in last 64 byte chunk
        uint4 count[2];   // 64bit counter for number of bits (lo, hi)
        uint4 state[4];   // digest so far
        uint1 digest[16]; // the result

        // low level logic operations
        static inline uint4 F(uint4 x, uint4 y, uint4 z);
        static inline uint4 G(uint4 x, uint4 y, uint4 z);
        static inline uint4 H(uint4 x, uint4 y, uint4 z);
        static inline uint4 I(uint4 x, uint4 y, uint4 z);
        static inline uint4 rotate_left(uint4 x, int n);
        static inline void FF(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
        static inline void GG(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
        static inline void HH(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
        static inline void II(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
    };



    class sha1 {
    public:
        sha1();
        std::string hash(const std::string &text) const;
        std::string hash(const std::ifstream &infile) const;

    private:
        typedef unsigned long int uint32;   /* just needs to be at least 32bit */
        typedef unsigned long long uint64;  /* just needs to be at least 64bit */

        void update(const std::string &s);
        void update(std::istream &is);
        std::string final();
        static std::string from_file(const std::string &filename);

        static const unsigned int DIGEST_INTS = 5;  /* number of 32bit integers per SHA1 digest */
        static const unsigned int BLOCK_INTS = 16;  /* number of 32bit integers per SHA1 block */
        static const unsigned int BLOCK_BYTES = BLOCK_INTS * 4;

        uint32 digest[DIGEST_INTS];
        std::string buffer;
        uint64 transforms;

        void reset();
        void transform(uint32 block[BLOCK_BYTES]);
        static void buffer_to_block(const std::string &buffer, uint32 block[BLOCK_BYTES]);
        static void read(std::istream &is, std::string &s, int max);
    };



    class sha256 {
    public:
        void init();
        std::string hash(std::string const &text) const;
        std::string hash(std::ifstream const &infile) const;

    protected:
        typedef unsigned char uint8;
        typedef unsigned int uint32;
        typedef unsigned long long uint64;
        static const unsigned int DIGEST_SIZE = (256 / 8);

        const static uint32 sha256_k[];
        static const unsigned int SHA224_256_BLOCK_SIZE = (512 / 8);

        void update(const unsigned char *message, unsigned int len);
        void final(unsigned char *digest);
        void transform(const unsigned char *message, unsigned int block_nb);
        unsigned int m_tot_len;
        unsigned int m_len;
        unsigned char m_block[2 * SHA224_256_BLOCK_SIZE];
        uint32 m_h[8];
    };

}



#endif //KC_DIGEST_H
