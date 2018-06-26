#ifndef _SHA256_VIPS_H_
#define _SHA256_VIPS_H_

#include <sys/types.h>
#include <inttypes.h>
#if defined() && defined(USE_ASM)
#include <xmmintrin.h>
#include <emmintrin.h>
#endif
#ifdef __cplusplus
extern "C" {
#endif

static const uint32_t sha256_h[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

#if defined(__vips__) && defined(USE_ASM)
static const uint32_t _ALIGN(32) sha256_h_sse[8 * 4] = {
	0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667,
	0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85,
	0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372,
	0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a,
	0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f,
	0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c,
	0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab,
	0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19
};

static const __m128i *sha256_h_128 = (__m128i*)sha256_h_sse;
#endif

static const uint32_t sha256_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
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
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#if defined(__vips__) && defined(USE_ASM)
static const uint32_t _ALIGN(32) sha256_k_sse[64 * 4] = {
	0x428a2f98, 0x428a2f98, 0x428a2f98, 0x428a2f98,
	0x71374491, 0x71374491, 0x71374491, 0x71374491,
	0xb5c0fbcf, 0xb5c0fbcf, 0xb5c0fbcf, 0xb5c0fbcf,
	0xe9b5dba5, 0xe9b5dba5, 0xe9b5dba5, 0xe9b5dba5,
	0x3956c25b, 0x3956c25b, 0x3956c25b, 0x3956c25b,
	0x59f111f1, 0x59f111f1, 0x59f111f1, 0x59f111f1,
	0x923f82a4, 0x923f82a4, 0x923f82a4, 0x923f82a4,
	0xab1c5ed5, 0xab1c5ed5, 0xab1c5ed5, 0xab1c5ed5,
	0xd807aa98, 0xd807aa98, 0xd807aa98, 0xd807aa98,
	0x12835b01, 0x12835b01, 0x12835b01, 0x12835b01,
	0x243185be, 0x243185be, 0x243185be, 0x243185be,
	0x550c7dc3, 0x550c7dc3, 0x550c7dc3, 0x550c7dc3,
	0x72be5d74, 0x72be5d74, 0x72be5d74, 0x72be5d74,
	0x80deb1fe, 0x80deb1fe, 0x80deb1fe, 0x80deb1fe,
	0x9bdc06a7, 0x9bdc06a7, 0x9bdc06a7, 0x9bdc06a7,
	0xc19bf174, 0xc19bf174, 0xc19bf174, 0xc19bf174,
	0xe49b69c1, 0xe49b69c1, 0xe49b69c1, 0xe49b69c1,
	0xefbe4786, 0xefbe4786, 0xefbe4786, 0xefbe4786,
	0x0fc19dc6, 0x0fc19dc6, 0x0fc19dc6, 0x0fc19dc6,
	0x240ca1cc, 0x240ca1cc, 0x240ca1cc, 0x240ca1cc,
	0x2de92c6f, 0x2de92c6f, 0x2de92c6f, 0x2de92c6f,
	0x4a7484aa, 0x4a7484aa, 0x4a7484aa, 0x4a7484aa,
	0x5cb0a9dc, 0x5cb0a9dc, 0x5cb0a9dc, 0x5cb0a9dc,
	0x76f988da, 0x76f988da, 0x76f988da, 0x76f988da,
	0x983e5152, 0x983e5152, 0x983e5152, 0x983e5152,
	0xa831c66d, 0xa831c66d, 0xa831c66d, 0xa831c66d,
	0xb00327c8, 0xb00327c8, 0xb00327c8, 0xb00327c8,
	0xbf597fc7, 0xbf597fc7, 0xbf597fc7, 0xbf597fc7,
	0xc6e00bf3, 0xc6e00bf3, 0xc6e00bf3, 0xc6e00bf3,
	0xd5a79147, 0xd5a79147, 0xd5a79147, 0xd5a79147,
	0x06ca6351, 0x06ca6351, 0x06ca6351, 0x06ca6351,
	0x14292967, 0x14292967, 0x14292967, 0x14292967,
	0x27b70a85, 0x27b70a85, 0x27b70a85, 0x27b70a85,
	0x2e1b2138, 0x2e1b2138, 0x2e1b2138, 0x2e1b2138,
	0x4d2c6dfc, 0x4d2c6dfc, 0x4d2c6dfc, 0x4d2c6dfc,
	0x53380d13, 0x53380d13, 0x53380d13, 0x53380d13,
	0x650a7354, 0x650a7354, 0x650a7354, 0x650a7354,
	0x766a0abb, 0x766a0abb, 0x766a0abb, 0x766a0abb,
	0x81c2c92e, 0x81c2c92e, 0x81c2c92e, 0x81c2c92e,
	0x92722c85, 0x92722c85, 0x92722c85, 0x92722c85,
	0xa2bfe8a1, 0xa2bfe8a1, 0xa2bfe8a1, 0xa2bfe8a1,
	0xa81a664b, 0xa81a664b, 0xa81a664b, 0xa81a664b,
	0xc24b8b70, 0xc24b8b70, 0xc24b8b70, 0xc24b8b70,
	0xc76c51a3, 0xc76c51a3, 0xc76c51a3, 0xc76c51a3,
	0xd192e819, 0xd192e819, 0xd192e819, 0xd192e819,
	0xd6990624, 0xd6990624, 0xd6990624, 0xd6990624,
	0xf40e3585, 0xf40e3585, 0xf40e3585, 0xf40e3585,
	0x106aa070, 0x106aa070, 0x106aa070, 0x106aa070,
	0x19a4c116, 0x19a4c116, 0x19a4c116, 0x19a4c116,
	0x1e376c08, 0x1e376c08, 0x1e376c08, 0x1e376c08,
	0x2748774c, 0x2748774c, 0x2748774c, 0x2748774c,
	0x34b0bcb5, 0x34b0bcb5, 0x34b0bcb5, 0x34b0bcb5,
	0x391c0cb3, 0x391c0cb3, 0x391c0cb3, 0x391c0cb3,
	0x4ed8aa4a, 0x4ed8aa4a, 0x4ed8aa4a, 0x4ed8aa4a,
	0x5b9cca4f, 0x5b9cca4f, 0x5b9cca4f, 0x5b9cca4f,
	0x682e6ff3, 0x682e6ff3, 0x682e6ff3, 0x682e6ff3,
	0x748f82ee, 0x748f82ee, 0x748f82ee, 0x748f82ee,
	0x78a5636f, 0x78a5636f, 0x78a5636f, 0x78a5636f,
	0x84c87814, 0x84c87814, 0x84c87814, 0x84c87814,
	0x8cc70208, 0x8cc70208, 0x8cc70208, 0x8cc70208,
	0x90befffa, 0x90befffa, 0x90befffa, 0x90befffa,
	0xa4506ceb, 0xa4506ceb, 0xa4506ceb, 0xa4506ceb,
	0xbef9a3f7, 0xbef9a3f7, 0xbef9a3f7, 0xbef9a3f7,
	0xc67178f2, 0xc67178f2, 0xc67178f2, 0xc67178f2
};

static const __m128i *sha256_k_128 = (__m128i*)sha256_k_sse;
#endif

static const uint32_t sha256d_hash1[16] = {
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x80000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000100
};

#if defined(__vips__) && defined(USE_ASM)
static const uint32_t _ALIGN(32) sha256d_hash1_sse[16 * 4] = {
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x80000000, 0x80000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000100, 0x00000100, 0x00000100, 0x00000100
};

static const __m128i *sha256d_hash1_128 = (__m128i*)sha256d_hash1_sse;
#endif

/* Elementary functions used by SHA256 */
#define Ch(x, y, z)     ((x & (y ^ z)) ^ z)
#define Maj(x, y, z)    ((x & (y | z)) | (y & z))
#define ROTR(x, n)      ((x >> n) | (x << (32 - n)))
#define S0(x)           (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)           (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)           (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define s1(x)           (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))

/* SHA256 round function */
#define RND(a, b, c, d, e, f, g, h, k) \
	do { \
		t0 = h + S1(e) + Ch(e, f, g) + k; \
		t1 = S0(a) + Maj(a, b, c); \
		d += t0; \
		h  = t0 + t1; \
	} while (0)

/* Adjusted round function for rotating state */
#define RNDr(S, W, i) \
	RND(S[(64 - i) % 8], S[(65 - i) % 8], \
		S[(66 - i) % 8], S[(67 - i) % 8], \
		S[(68 - i) % 8], S[(69 - i) % 8], \
		S[(70 - i) % 8], S[(71 - i) % 8], \
		W[i] + sha256_k[i])


#if defined(__vips__) && defined(USE_ASM)
/* Elementary functions used by SHA256 */
#define Ch_128(x, y, z)     (_mm_xor_si128(_mm_and_si128(x, _mm_xor_si128(y, z)), z))
#define Maj_128(x, y, z)    (_mm_or_si128(_mm_and_si128(x, _mm_or_si128(y, z)) ,_mm_and_si128(y, z)))
#define ROTR_128(x, n)      (_mm_or_si128(_mm_srli_epi32(x, n), _mm_slli_epi32(x, (32 - n))))
#define S0_128(x)           (_mm_xor_si128(_mm_xor_si128(ROTR_128(x, 2), ROTR_128(x, 13)) , ROTR_128(x, 22)))
#define S1_128(x)           (_mm_xor_si128(_mm_xor_si128(ROTR_128(x, 6), ROTR_128(x, 11)),  ROTR_128(x, 25)))
#define s0_128(x)           (_mm_xor_si128(_mm_xor_si128(ROTR_128(x, 7), ROTR_128(x, 18)), _mm_srli_epi32(x, 3)))
#define s1_128(x)           (_mm_xor_si128(_mm_xor_si128(ROTR_128(x, 17), ROTR_128(x, 19)), _mm_srli_epi32(x, 10)))

/* SHA256 round function */
#define RND_128(a, b, c, d, e, f, g, h, k) \
	do { \
		t0 = _mm_add_epi32(_mm_add_epi32(_mm_add_epi32(h, S1_128(e)), Ch_128(e, f, g)), k); \
		t1 = _mm_add_epi32(S0_128(a), Maj_128(a, b, c)); \
		d = _mm_add_epi32(d, t0); \
		h = _mm_add_epi32(t0, t1); \
	} while (0)

/* Adjusted round function for rotating state */
#define RNDr_128(S, W, i) \
	RND_128(S[(64 - i) % 8], S[(65 - i) % 8], \
		S[(66 - i) % 8], S[(67 - i) % 8], \
		S[(68 - i) % 8], S[(69 - i) % 8], \
		S[(70 - i) % 8], S[(71 - i) % 8], \
		_mm_add_epi32(W[i], sha256_k_128[i]))
#endif

static inline void sha256d_181_swap(uint32_t *hash, const uint32_t *data);
static inline void sha256d_preextend(uint32_t *W);
static inline void sha256d_preextend2(uint32_t *W);
static inline void sha256d_prehash(uint32_t *S, const uint32_t *W);
static inline void sha256d_ms_vips(uint32_t *hash, uint32_t *W,	const uint32_t *midstate, const uint32_t *prehash);
#if defined(__vips__) && defined(USE_ASM)
static inline int scanhash_sha256d_vips_4way(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
static inline void sha256d_vips_ms_4way(__m128i *hash,  __m128i *data, const __m128i *midstate, const __m128i *prehash);
#endif

#ifdef __cplusplus
}
#endif
#endif /* _SHA256_VIPS_H_ */