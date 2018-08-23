#ifndef _A_CRYPTO_H_INCLUDED_
#define _A_CRYPTO_H_INCLUDED_

#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "a_core.h"

#define A_CRYPTO_RSA_PADDING_PSS    0
#define A_CRYPTO_RSA_PADDING_PKCS1  1

/*MUST be in order*/
#define A_CRYPTO_NID_RSA            0
#define A_CRYPTO_NID_EC             1
#define A_CRYPTO_NID_RSAPSS         2
#define A_CRYPTO_NID_SM             3
#define A_CRYPTO_NID_MAX            4

#define A_CRYPTO_NID_SHA256         5
#define A_CRYPTO_NID_SHA384         6
#define A_CRYPTO_NID_SHA512         7
#define A_CRYPTO_NID_SHA1           8
#define A_CRYPTO_NID_MD5            9
#define A_CRYPTO_NID_MD5_SHA1       10
#define A_CRYPTO_NID_SM3            11


#define A_CRYPTO_MAX_EC_PUB_LEN     133//secp521
#define A_CRYPTO_MAX_MD_LEN         64
#define A_CRYPTO_MAX_KEY_LEN        64
#define A_CRYPTO_MAX_IV_LEN         16
enum {

    A_CRYPTO_CIPHER_RSA         = (1U<<0),
    A_CRYPTO_CIPHER_ECDHE       = (1U<<1),
    A_CRYPTO_CIPHER_ECDH        = (1U<<2),
    A_CRYPTO_CIPHER_ECC         = (1U<<3),
    A_CRYPTO_CIPHER_ASYN_MAX             ,

    A_CRYPTO_CIPHER_TLS1        = (1U<<5),
    A_CRYPTO_CIPHER_TLS1_1      = (1U<<6),
    A_CRYPTO_CIPHER_TLS1_2      = (1U<<7),
    A_CRYPTO_CIPHER_GENERIC     = A_CRYPTO_CIPHER_TLS1|A_CRYPTO_CIPHER_TLS1_1|A_CRYPTO_CIPHER_TLS1_2,
    A_CRYPTO_CIPHER_TLS1_3      = (1U<<8),
    A_CRYPTO_CIPHER_SM          = (1U<<9),

    A_CRYPTO_CIPHER_CBC         = (1U<<10),
    A_CRYPTO_CIPHER_STREAM      = (1U<<11),
    A_CRYPTO_CIPHER_GCM         = (1U<<12),
};

typedef struct
{
    u8 *p;
    u8 *c;
    u32 p_len;
    u32 c_len;
    u32 type;

    struct {
        void *md;
        void *key;
        u8   *tbs;
        u32  tbs_len;
        u32  mode;
        u8   *out;
        u32  *out_len;
    }async;

}crypto_info_t;

typedef struct
{
    s8 *name;
    u32 tls_nid;
    u32 openssl_nid;
    u32 field_len;
    const void *group;
}a_group_t;

typedef struct
{
    u32 nid;
    u32 opentls_nid;
    u32 block_size;
    u32 hash_size;
    u8 rsa_sign_add[19];
    u32 add_len;
    const void *md;//EVP_MD
}a_md_t;

typedef struct
{
    s8 *name;
    u32 tls_nid;
    u32 openssl_nid;
    u32 key_len;
    u32 iv_len;
    u32 block_size;
    u32 md_nid;
    u32 flag;
    u32 sign;
    s32 (*parse_cke)(void *arg, u8 *in, u32 in_len);
    s32 (*gen_ske)(void *arg, u8 *out, u32 *out_len);
    s32 (*enc)(void *arg, crypto_info_t *info);
    s32 (*dec)(void *arg, crypto_info_t *info);

    /*need init*/
    const void *cipher;//EVP_CIPHER
    a_md_t     *md;
    void       *next;
}a_cipher_t;

enum
{
    A_CRYPTO_GROUP_ID_SECP192R1 = 0x0013,
    A_CRYPTO_GROUP_ID_SECP256R1 = 0x0017,
    A_CRYPTO_GROUP_ID_SECP384R1 = 0x0018,
    A_CRYPTO_GROUP_ID_SECP521R1 = 0x0019,
    A_CRYPTO_GROUP_ID_X25519    = 0x001D,
};

a_md_t *a_md5;
a_md_t *a_sha1;
a_md_t *a_sha256;
a_md_t *a_sha384;
a_md_t *a_sha512;
typedef s32 (*crypto_proc)(void *arg, crypto_info_t *info);
typedef s32 (*md_proc)(a_md_t *md, u8 *in, u32 in_len, u8 *out);

a_group_t *a_crypto_get_group_by_tls_id(u32 tls_id);
a_group_t *a_crypto_get_group_by_index(u32 index);
u8 a_crypto_get_group_index_by_tls_id(u32 tls_id);
s32 a_crypto_gen_ec_pub(a_group_t *group, u8 **prv, u8 **pub, u32 *prv_len, u32 *pub_len);
s32 a_crypto_calc_ec_shared(a_group_t *group, u8 *scale, u32 scale_len, u8 *f_point, u32 f_point_len, u8 *out, u32 *out_len);
void *a_crypto_find_cipher_by_nid(u32 tls_nid);
void *a_crypto_get_cipher_by_index(u32 index);
void *a_crypto_find_md(u32 nid);
s32 a_md_do_digest(a_md_t *md, u8 *in, u32 in_len, u8 *out);
s32 a_crypto_rsa_dec(void *arg, crypto_info_t *info);
s32 a_crypto_rsa_sign(void *arg, crypto_info_t *info);
s32 a_crypto_ec_sign(void *arg, crypto_info_t *info);
s32 a_crypto_sm2_sign(void *arg, crypto_info_t *info);
s32 a_crypto_sm2_dec(void *arg, crypto_info_t *info);
s32 a_crypto_hmac(a_md_t *md, u8 *sec, u32 sec_len, u8 *data, u32 data_len, u8 *out);
void a_tls_init_crypto_env();

#ifdef NID_X25519
void *a_crypto_gen_pkey(a_group_t *group, u8 *in, u32 in_len);
void* a_crypto_gen_ec_pub_pkey(a_group_t *group, u8 *out, u32 *out_len);
s32 a_crypto_calc_ec_shared_pkey(u32 nid, void *_pri, void *_pub, u8 *pms, u32 *pms_len);
#endif

/*kdf*/
s32 a_crypto_HKDF_expand(a_md_t *md, u8 *info, u32 info_len, u8 *key, u32 key_len, u8 *out, u32 out_len);
s32 a_crypto_HKDF_extract(a_md_t *md, u8 *salt, u32 salt_len, u8 *key, u32 key_len, u8 *out);
s32 a_crypto_phash(a_md_t *op, unsigned char *sec,
    int sec_len, u8 *seed, u32 seed_len, u8 *out, u32 olen);

#endif
