#include "a_crypto.h"
#include "a_tls.h"

#define for_each_cipher(cipher)   \
    for(i = 0; i < sizeof(a_ciphers)/sizeof(a_cipher_t) && (cipher = &a_ciphers[i]) != NULL; i++)
#define for_each_md(md)   \
    for(i = 0; i < sizeof(a_md)/sizeof(a_md_t) && (md = &a_md[i]) != NULL; i++)

crypto_proc _a_tls_dec_cbc;
crypto_proc _a_tls_enc_cbc;
crypto_proc _a_tls_dec_gcm;
crypto_proc _a_tls_enc_gcm;
crypto_proc _a_tls13_enc_gcm;
crypto_proc _a_tls13_dec_gcm;

crypto_proc _a_crypto_rsa_sign;
crypto_proc _a_crypto_rsa_dec;
crypto_proc _a_crypto_ec_sign;
crypto_proc _a_crypto_sm2_sign;
crypto_proc _a_crypto_sm2_dec;
md_proc     _a_md_proc;

s32 a_tls_dec_cbc(void *arg, crypto_info_t *info)
{
    return _a_tls_dec_cbc(arg, info);
}

s32 a_tls_enc_cbc(void *arg, crypto_info_t *info)
{
    return _a_tls_enc_cbc(arg, info);
}

s32 a_tls_dec_gcm(void *arg, crypto_info_t *info)
{
    return _a_tls_dec_gcm(arg, info);
}

s32 a_tls_enc_gcm(void *arg, crypto_info_t *info)
{
    return _a_tls_enc_gcm(arg, info);
}

s32 a_tls13_enc_gcm(void *arg, crypto_info_t *info)
{
    return _a_tls13_enc_gcm(arg, info);
}

s32 a_tls13_dec_gcm(void *arg, crypto_info_t *info)
{
    return _a_tls13_dec_gcm(arg, info);
}

s32 a_crypto_rsa_sign(void *arg, crypto_info_t *info)
{
    return _a_crypto_rsa_sign(arg, info);
}

s32 a_crypto_rsa_dec(void *arg, crypto_info_t *info)
{
    return _a_crypto_rsa_dec(arg, info);
}

s32 a_crypto_ec_sign(void *arg, crypto_info_t *info)
{
    return _a_crypto_ec_sign(arg, info);
}

s32 a_crypto_sm2_sign(void *arg, crypto_info_t *info)
{
    return _a_crypto_sm2_sign(arg, info);
}

s32 a_crypto_sm2_dec(void *arg, crypto_info_t *info)
{
    return _a_crypto_sm2_dec(arg, info);
}

s32 a_md_do_digest(a_md_t *md, u8 *in, u32 in_len, u8 *out)
{
    return _a_md_proc(md, in, in_len, out);
}

a_md_t *a_md5    = NULL;
a_md_t *a_sha1   = NULL;
a_md_t *a_sha256 = NULL;
a_md_t *a_sha384 = NULL;
a_md_t *a_sha512 = NULL;

a_group_t a_groups[A_TLS_MAX_GROUP] =
{
    {
        NULL,
        0,
        0,
        0,
        NULL,
    },
    {
        "secp256r1",
        A_CRYPTO_GROUP_ID_SECP256R1,
        NID_X9_62_prime256v1,
        0,
        NULL,
    },

    {
        "secp384r1",
        A_CRYPTO_GROUP_ID_SECP384R1,
        NID_secp384r1,
        0,
        NULL,
    },

    {
        "secp521r1",
        A_CRYPTO_GROUP_ID_SECP521R1,
        NID_secp521r1,
        0,
        NULL,
    },

#ifdef NID_X25519
    {
        "X25519",
        A_CRYPTO_GROUP_ID_X25519,
        NID_X25519,
        0,
        NULL,
    },
#endif
};

a_cipher_t a_ciphers[] =
{
    /*TLS 1.3 ciphers*/
    {
        "TLS_AES_128_GCM_SHA256",
        0x1301, NID_aes_128_gcm, 16, 12, 16, A_CRYPTO_NID_SHA256,
        A_CRYPTO_CIPHER_TLS1_3|A_CRYPTO_CIPHER_ECDHE|A_CRYPTO_CIPHER_GCM,
        0,
        NULL,NULL,
        a_tls13_enc_gcm, a_tls13_dec_gcm,
        NULL,NULL,NULL,
    },

    {
        "TLS_AES_256_GCM_SHA384",
        0x1302, NID_aes_256_gcm, 32, 12, 16, A_CRYPTO_NID_SHA384,
        A_CRYPTO_CIPHER_TLS1_3|A_CRYPTO_CIPHER_ECDHE|A_CRYPTO_CIPHER_GCM,
        0,
        NULL,NULL,
        a_tls13_enc_gcm, a_tls13_dec_gcm,
        NULL,NULL,NULL,
    },

    /*TLS1.2's main ciphers*/


    /*ECDHE_ECDSA*/
    {
        "ECDHE_ECDHE_WITH_AES_256_GCM_SHA384",
        0xc02c, NID_aes_256_gcm, 32, 12, 16, A_CRYPTO_NID_SHA384,
        A_CRYPTO_CIPHER_TLS1_2|A_CRYPTO_CIPHER_ECDHE|A_CRYPTO_CIPHER_GCM,
        A_CRYPTO_NID_EC,
        a_tls_process_cke_ecdh, NULL,
        a_tls_enc_gcm,a_tls_dec_gcm,
        NULL,NULL,NULL,
    },

    {
        "ECDHE_ECDHE_WITH_AES_128_GCM_SHA256",
        0xc02c, NID_aes_128_gcm, 16, 12, 16, A_CRYPTO_NID_SHA256,
        A_CRYPTO_CIPHER_TLS1_2|A_CRYPTO_CIPHER_ECDHE|A_CRYPTO_CIPHER_GCM,
        A_CRYPTO_NID_EC,
        a_tls_process_cke_ecdh, NULL,
        a_tls_enc_gcm, a_tls_dec_gcm,
        NULL,NULL,NULL,
    },

    {
        "ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc02f, NID_aes_128_gcm, 16, 12, 16, A_CRYPTO_NID_SHA256,
        A_CRYPTO_CIPHER_TLS1_2|A_CRYPTO_CIPHER_ECDHE|A_CRYPTO_CIPHER_GCM,
        A_CRYPTO_NID_RSA,
        a_tls_process_cke_ecdh, NULL,
        a_tls_enc_gcm,a_tls_dec_gcm,
        NULL,NULL,NULL,
    },

    {
        "ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xc030, NID_aes_256_gcm, 32, 12, 16, A_CRYPTO_NID_SHA384,
        A_CRYPTO_CIPHER_TLS1_2|A_CRYPTO_CIPHER_ECDHE|A_CRYPTO_CIPHER_GCM,
        A_CRYPTO_NID_RSA,
        a_tls_process_cke_ecdh, NULL,
        a_tls_enc_gcm,a_tls_dec_gcm,
        NULL,NULL,NULL,
    },

    /*TLSv1 and TLSv1.1's main cipers and TLS1.2's back ciphers.
     *I'm not trying to support GCM mode under TLS1.2.
     */

    /*ECDHE-ECDSA-AES128-SHA*/
    {
        "ECDHE_ECDSA_WITH_AES128_SHA",
        0xc009, NID_aes_128_cbc, 16, 16, 16, A_CRYPTO_NID_SHA1,
        A_CRYPTO_CIPHER_GENERIC|A_CRYPTO_CIPHER_ECDHE|A_CRYPTO_CIPHER_CBC,
        A_CRYPTO_NID_EC,
        a_tls_process_cke_ecdh, NULL,
        a_tls_enc_cbc, a_tls_dec_cbc,
        NULL,NULL,NULL,
    },

    /*ECDHE-ECDSA-AES128-SHA256*/
    {
        "ECDHE_ECDSA_WITH_AES128_SHA256",
        0xc023, NID_aes_128_cbc, 16, 16, 16, A_CRYPTO_NID_SHA256,
        A_CRYPTO_CIPHER_GENERIC|A_CRYPTO_CIPHER_ECDHE|A_CRYPTO_CIPHER_CBC,
        A_CRYPTO_NID_EC,
        a_tls_process_cke_ecdh, NULL,
        a_tls_enc_cbc, a_tls_dec_cbc,
        NULL,NULL,NULL,
    },

    /*ECDHE-RSA-AES128-SHA*/
    {
        "ECDHE_RSA_WITH_AES128_SHA",
        0xc013, NID_aes_128_cbc, 16, 16, 16, A_CRYPTO_NID_SHA1,
        A_CRYPTO_CIPHER_GENERIC|A_CRYPTO_CIPHER_ECDHE|A_CRYPTO_CIPHER_CBC,
        A_CRYPTO_NID_RSA,
        a_tls_process_cke_ecdh, NULL,
        a_tls_enc_cbc, a_tls_dec_cbc,
        NULL,NULL,NULL,
    },

    /*ECDHE-RSA-AES128-SHA256*/
    {
        "ECDHE_RSA_WITH_AES128_SHA256",
        0xc027, NID_aes_128_cbc, 16, 16, 16, A_CRYPTO_NID_SHA256,
        A_CRYPTO_CIPHER_GENERIC|A_CRYPTO_CIPHER_ECDHE|A_CRYPTO_CIPHER_CBC,
        A_CRYPTO_NID_RSA,
        a_tls_process_cke_ecdh, NULL,
        a_tls_enc_cbc, a_tls_dec_cbc,
        NULL,NULL,NULL,
    },

    /*ECDHE-ECDSA-AES256-SHA*/
    {
        "ECDHE_ECDSA_WITH_AES256_SHA",
        0xc00a, NID_aes_256_cbc, 32, 16, 16, A_CRYPTO_NID_SHA1,
        A_CRYPTO_CIPHER_GENERIC|A_CRYPTO_CIPHER_ECDHE|A_CRYPTO_CIPHER_CBC,
        A_CRYPTO_NID_EC,
        a_tls_process_cke_ecdh, NULL,
        a_tls_enc_cbc, a_tls_dec_cbc,
        NULL,NULL,NULL,
    },

    /*RSA*/
    {
        "RSA_WITH_AES_128_GCM_SHA256",
        0x009c, NID_aes_128_gcm, 16, 12, 16, A_CRYPTO_NID_SHA256,
        A_CRYPTO_CIPHER_GENERIC|A_CRYPTO_CIPHER_RSA|A_CRYPTO_CIPHER_GCM,
        0,
        a_tls_process_cke_rsa, NULL,
        a_tls_enc_gcm,a_tls_dec_gcm,
        NULL,NULL,NULL,
    },

    {
        "RSA_WITH_AES_256_GCM_SHA384",
        0x009d, NID_aes_256_gcm, 32, 12, 16, A_CRYPTO_NID_SHA384,
        A_CRYPTO_CIPHER_GENERIC|A_CRYPTO_CIPHER_RSA|A_CRYPTO_CIPHER_GCM,
        0,
        a_tls_process_cke_rsa, NULL,
        a_tls_enc_gcm,a_tls_dec_gcm,
        NULL,NULL,NULL,
    },

    /*RSA_AES_128_SHA*/
    {
        "RSA_WITH_AES_128_SHA",
        0x002f, NID_aes_128_cbc, 16, 16, 16, A_CRYPTO_NID_SHA1,
        A_CRYPTO_CIPHER_GENERIC|A_CRYPTO_CIPHER_RSA|A_CRYPTO_CIPHER_CBC,
        0,
        a_tls_process_cke_rsa, NULL,
        a_tls_enc_cbc, a_tls_dec_cbc,
        NULL,NULL,NULL,
    },

    /*RSA_AES_128_SHA256*/
    {
        "RSA_WITH_AES_128_SHA256",
        0x003c, NID_aes_128_cbc, 16, 16, 16, A_CRYPTO_NID_SHA256,
        A_CRYPTO_CIPHER_GENERIC|A_CRYPTO_CIPHER_RSA|A_CRYPTO_CIPHER_CBC,
        0,
        a_tls_process_cke_rsa, NULL,
        a_tls_enc_cbc, a_tls_dec_cbc,
        NULL,NULL,NULL,
    },

    /*RSA_AES_256_SHA*/
    {
        "RSA_WITH_AES_256_SHA",
        0x0035, NID_aes_256_cbc, 32, 16, 16, A_CRYPTO_NID_SHA1,
        A_CRYPTO_CIPHER_GENERIC|A_CRYPTO_CIPHER_RSA|A_CRYPTO_CIPHER_CBC,
        0,
        a_tls_process_cke_rsa, NULL,
        a_tls_enc_cbc, a_tls_dec_cbc,
        NULL,NULL,NULL,
    },

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    /*GM1.1*/
    {
        "ECC_SM2_WITH_SM4_SM3",
        0xe013, NID_sm4_cbc, 16, 16, 16, A_CRYPTO_NID_SM3,
        A_CRYPTO_CIPHER_SM|A_CRYPTO_CIPHER_ECC|A_CRYPTO_CIPHER_CBC,
        A_CRYPTO_NID_SM,
        a_tls_process_cke_ecc, NULL,
        a_tls_enc_cbc, a_tls_dec_cbc,
        NULL,NULL,NULL,
    }
#endif
};

a_md_t a_md[] =
{
    {
        A_CRYPTO_NID_MD5_SHA1, NID_md5_sha1, 64, 36,
        {0},0,NULL,
    },

    {
        A_CRYPTO_NID_MD5, NID_md5, 64, 16,
        {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2a, 0x86, 0x48, 0x02, 0x05, 0x05, 0x00, 0x04, 0x14},
        15,NULL,
    },
    {
        A_CRYPTO_NID_SHA1, NID_sha1,   64, 20,
        {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
        15,NULL,
    },
    {
        A_CRYPTO_NID_SHA256, NID_sha256, 64, 32,
        {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
        19,NULL,
    },
    {
        A_CRYPTO_NID_SHA384, NID_sha384, 64, 48,
        {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
        19,NULL,
    },
    {
        A_CRYPTO_NID_SHA512, NID_sha512, 128, 64,
        {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
        19,NULL,
    },

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    {
        A_CRYPTO_NID_SM3, NID_sm3, 64, 32,
        {0},
        0, NULL,
    },
#endif
};

void *a_crypto_get_cipher_by_index(u32 index)
{
    if (index < sizeof(a_ciphers)/sizeof(a_cipher_t)) {
        return &a_ciphers[index];
    }

    return NULL;
}

void *a_crypto_find_cipher_by_nid(u32 tls_nid)
{
    u32 i;

    for(i = 0; i < sizeof(a_ciphers)/sizeof(a_cipher_t); i++)
    {
        if(tls_nid == a_ciphers[i].tls_nid) {
            return &a_ciphers[i];
        }
    }

    return NULL;
}

void *a_crypto_find_md(u32 nid)
{
    u32 i;

    for(i = 0; i < sizeof(a_md)/sizeof(a_md_t); i++)
    {
        if(nid == a_md[i].nid) {
            return &a_md[i];
        }
    }

    return NULL;
}

/*We asume digest always return success to make us code easly*/
s32 a_md_do_digest_openssl(a_md_t *md, u8 *in, u32 in_len, u8 *out)
{
    u32 tmp_len;

    if (md->nid == A_CRYPTO_NID_MD5_SHA1) {
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
        if (!EVP_Digest(in, in_len, out, &tmp_len, EVP_md5_sha1(), NULL)) {
            goto err;
        }
#else
        if(!EVP_Digest(in, in_len, out, &tmp_len, EVP_md5(), NULL)) {
            goto err;
        }

        if(!EVP_Digest(in, in_len, out + tmp_len, &tmp_len, EVP_sha1(), NULL)) {
            goto err;
        }
#endif
    } else {

        if(!EVP_Digest(in, in_len, out, &tmp_len, md->md, NULL)) {
            goto err;
        }
    }

    return A_TLS_OK;

err:
    return A_TLS_ERR;
}

s32 a_crypto_do_ec_mul(a_group_t *group, u8 *scale, u32 scale_len,u8 *f_point, u32 f_point_len, u8 *out)
{
    BN_CTX *ctx = NULL;
    EC_POINT *pub_key = NULL, *r = NULL;
    BIGNUM *s = NULL;
    s32 ret;

    ctx     = BN_CTX_new();
    s       = BN_new();
    pub_key = EC_POINT_new(group->group);
    r       = EC_POINT_new(group->group);

    if (!ctx
        || !s
        || !pub_key
        || !r) {
        goto err;
    }

    if(!BN_bin2bn(scale, scale_len, s)) {
        goto err;
    }

    if(!EC_POINT_oct2point(group->group, pub_key, f_point, f_point_len, ctx))
    {
        goto err;
    }

    if (!EC_POINT_mul(
            group->group,
            r,
            NULL,/*generator scale*/
            pub_key,
            s,
            ctx)) {
        goto err;
    }
    if (!EC_POINT_point2oct(group->group, r, POINT_CONVERSION_UNCOMPRESSED,
                            out, group->field_len * 2 + 1, NULL))
        goto err;

    ret = A_TLS_OK;

free:
    if (ctx) {
        BN_CTX_free(ctx);
    }

    if (s) {
        BN_free(s);
    }

    if (pub_key) {
        EC_POINT_free(pub_key);
    }

    if (r) {
        EC_POINT_free(r);
    }
    return ret;
err:
    ret = A_TLS_ERR;
    goto free;
}

s32 a_crypto_calc_ec_shared(a_group_t *group, u8 *scale, u32 scale_len, u8 *f_point, u32 f_point_len, u8 *out, u32 *out_len)
{
    u8 tmp[A_CRYPTO_MAX_EC_PUB_LEN];

#ifdef TLS_DEBUG
    {
        u32 i;
        printf("ec scale\n");
        for(i=0;i<scale_len;i++)
        {
            printf("%02X", scale[i]);
        }
        printf("\n");
    }
#endif
    if (a_crypto_do_ec_mul(group, scale, scale_len, f_point, f_point_len, tmp)
                               != A_TLS_OK)
    {
        return A_TLS_ERR;
    }
#ifdef TLS_DEBUG
    {
        u32 i;
        printf("after ec\n");
        for(i=0;i<32*2+1;i++)
        {
            printf("%02X", tmp[i]);
        }
        printf("\n");
    }
#endif

    /*Only get X*/
    memcpy(out, tmp + 1, group->field_len);
    *out_len = group->field_len;
    return A_TLS_OK;
}

#ifdef NID_X25519
s32 a_crypto_calc_ec_shared_pkey(u32 nid, void *_pri, void *_pub, u8 *pms, u32 *pms_len)
{
    EVP_PKEY_CTX *pctx;
    size_t tmp;

    pctx = EVP_PKEY_CTX_new(_pri, NULL);
    if (pctx == NULL) {
        return A_TLS_ERR;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0
        || EVP_PKEY_derive_set_peer(pctx, _pub) <= 0
        || EVP_PKEY_derive(pctx, pms, &tmp) <= 0)
    {
        goto err;
    }

    *pms_len = tmp;
    EVP_PKEY_CTX_free(pctx);
    return A_TLS_OK;
err:
    EVP_PKEY_CTX_free(pctx);
    return A_TLS_ERR;
}

void *a_crypto_gen_pkey(a_group_t *group, u8 *in, u32 in_len)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (NID_X25519 == group->openssl_nid) {

        pkey = EVP_PKEY_new();
        if (!pkey) {
            printf("a_crypto_gen_peky %d\n",__LINE__);
            goto err;
        }

        if(!EVP_PKEY_set_type(pkey, group->openssl_nid)) {
            printf("a_crypto_gen_peky %d\n",__LINE__);
            goto err;
        }
    }
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL) {
        printf("gen pkey err %d\n",__LINE__);
        goto err;
    }

    if (!EVP_PKEY_set1_tls_encodedpoint(pkey, in, in_len)) {
        printf("gen pkey err %d\n",__LINE__);
        goto err;
    }

    EVP_PKEY_CTX_free(pctx);
    return pkey;
err:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }

    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
    return NULL;
}

/*EVP schedule*/
void* a_crypto_gen_ec_pub_pkey(a_group_t *group, u8 *out, u32 *out_len)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    u8 *tmp = NULL;

    if (group->openssl_nid == NID_X25519) {
        pctx = EVP_PKEY_CTX_new_id(group->openssl_nid, NULL);
    } else{
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        printf("EVP_PKEY_keygen_init err\n");
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    if (group->openssl_nid != NID_X25519
        && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, group->openssl_nid) <= 0) {
        printf("EVP_PKEY_CTX_set_ec_paramgen_curve_nid err\n");
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        printf("EVP_PKEY_keygen err\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    *out_len = EVP_PKEY_get1_tls_encodedpoint(pkey, &tmp);
    if (*out_len == 0) {
        printf("EVP_PKEY_get1_tls_encodedpoint err\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    memcpy(out ,tmp, *out_len);
    OPENSSL_free(tmp);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}
#endif
s32 a_crypto_gen_ec_pub(a_group_t *group, u8 **prv, u8 **pub, u32 *prv_len, u32 *pub_len)
{
    s32 ret = A_TLS_ERR;
    const EC_POINT *basepoint;
    EC_POINT *pub_key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *priv_key = NULL, *order = NULL;

    ctx         = BN_CTX_new();
    priv_key    = BN_new();
    order       = BN_new();

    if (ctx == NULL
        || priv_key == NULL
        || order == NULL)
    {
        goto err;
    }

    if ((basepoint = EC_GROUP_get0_generator(group->group))
        == NULL)
    {
        printf("err a_crypto_gen_ec_pub %d group:%p\n",__LINE__, group->group);
        goto err;
    }

    /*Alloc result's memory*/
    if ((pub_key = EC_POINT_new(group->group))
        == NULL)
    {
        printf("err a_crypto_gen_ec_pub %d\n",__LINE__);
        goto err;
    }

    /*Alloc priv_key's memory*/
    if (!EC_GROUP_get_order(group->group, order, ctx)
        || !BN_rand_range(priv_key, order))
    {
        printf("err a_crypto_gen_ec_pub %d\n",__LINE__);
        goto err;
    }

    /*do  "priv_key*basepoint" */
    if (!EC_POINT_mul(
            group->group,
            pub_key,
            NULL,/*generator scale*/
            basepoint,
            priv_key,
            ctx))
    {
        printf("err a_crypto_gen_ec_pub %d\n",__LINE__);
        goto err;
    }

    //EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx);

    *pub_len = group->field_len * 2 + 1;
    *prv_len = BN_num_bytes(priv_key);

    *prv = a_tls_malloc(BN_num_bytes(priv_key));
    *pub = a_tls_malloc(*pub_len);

    if (*prv == NULL
        || *pub == NULL)
        goto err;

    if(!BN_bn2bin(priv_key, *prv))
        goto err;


    EC_POINT_point2oct(group->group, pub_key, POINT_CONVERSION_UNCOMPRESSED,
                       *pub, *pub_len, NULL);

    ret = A_TLS_OK;
end:
    if (ctx) {
        BN_CTX_free(ctx);
    }

    if (priv_key) {
        BN_free(priv_key);
    }

    if (order) {
        BN_free(order);
    }

    return ret;
err:
    if (*prv) {
        a_tls_free(*prv);
        *prv = NULL;
    }
    if (*pub) {
        a_tls_free(*pub);
        *pub = NULL;
    }
    ret = A_TLS_ERR;
    goto end;
}

a_group_t *a_crypto_get_group_by_tls_id(u32 tls_id)
{
    u32 i;

    for(i = 0; i < sizeof(a_groups)/sizeof(a_group_t); i++)
    {
        if (a_groups[i].tls_nid == tls_id) {
            return &a_groups[i];
        }
    }

    return NULL;
}
a_group_t *a_crypto_get_group_by_index(u32 index)
{
    if (index > A_TLS_MAX_GROUP) {
        return NULL;
    }

    return &a_groups[index];
}


u8 a_crypto_get_group_index_by_tls_id(u32 tls_id)
{
    u32 i;

    for(i = 0; i < sizeof(a_groups)/sizeof(a_group_t); i++)
    {
        if (a_groups[i].tls_nid == tls_id) {
            return i;
        }
    }

    return 0;
}

s32 a_crypto_hmac(a_md_t *md, u8 *sec, u32 sec_len, u8 *data, u32 data_len, u8 *out)
{
    u32 outlen;

    HMAC(md->md, sec, sec_len, data, data_len, out, &outlen);
    return A_TLS_OK;
}

void mgf1(a_md_t *md, u8 *dst, u32 dst_len, u8 *src, u32 src_len)
{
    unsigned char tmp[A_CRYPTO_MAX_MD_LEN] = {0}, tmp2[A_CRYPTO_MAX_MD_LEN];
    unsigned char *p = dst, *ctr;
    unsigned int mask_len, hash_len = src_len, i;

    memcpy(tmp, src, src_len);
    ctr = tmp + src_len;

    while((int)dst_len > 0) {
        a_md_do_digest(md ,tmp, src_len + 4, tmp2);
        mask_len = dst_len < hash_len ? dst_len : hash_len;

        for(i = 0; i < mask_len; i++) {
            *p++ ^= tmp2[i];
        }
        dst_len -= mask_len;
        ctr[3]++;
    }
}

s32 light_rsa_add_pkcs1_padding(a_md_t *md, u8 *in, u32 in_len, u8 *out, u32 out_len)
{
    u8 *p = out;

    *p++ = 0x00;
    *p++ = 0x01;

    memset(p, 0xff, out_len - in_len - 3 - md->add_len);
    p += out_len - in_len - 3 - md->add_len;
    *p++ = 0;
    memcpy(p, md->rsa_sign_add, md->add_len);
    p += md->add_len;
    memcpy(p, in, in_len);
    return A_TLS_OK;
}

s32 light_rsa_add_pss_padding(a_md_t *md, u8 *in, u32 in_len, u8 *out, u32 out_len)
{
    u8 *salt;
    u8 tmp[8 + A_CRYPTO_MAX_MD_LEN*2]={0};
    u8 *p = out;
    u32 hash_len = md->hash_size;

    memset(p, 0, out_len - 2 - hash_len * 2);

    /*radnom salt*/
    salt = (p + out_len - 2 - hash_len * 2);

    *salt++ = 0x01;

    /*Random*/
    memset(salt, 0x12, hash_len);

    memcpy(tmp + 8, in, hash_len);
    memcpy(tmp + 8 + hash_len, salt, hash_len);
    a_md_do_digest(md , tmp, 8 + hash_len + hash_len, p + out_len - hash_len - 1);

#ifdef TLS_DEBUG
    {
        u32 k;
        printf("rsa pss md in\n");
        for(k=0;k<8+hash_len+hash_len;k++)
            {
                printf("%02X", tmp[k]);
            }
        printf("\n");
    }

    {
        u32 k;
        printf("rsa pss m' \n");
        for(k=0;k<hash_len;k++)
            {
                printf("%02X", (p + out_len - hash_len - 1)[k]);
            }
        printf("\n");
    }
#endif
    mgf1(md, out, out_len - hash_len - 1, p + out_len - hash_len - 1, hash_len);
    out[out_len - 1] = 0xBC;
    out[0] &= 0xFF >> 1;

    return A_TLS_OK;
    /*Set the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB to zero.*/
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
s32 a_crypto_sm2_sign_openssl(void *arg, crypto_info_t *info)
{
    EC_KEY *ec;
    EVP_PKEY *ec_key;
    ECDSA_SIG *sig = NULL;

    void *key  = info->async.key;
    u8 *in     = info->async.tbs;
    u32 in_len = info->async.tbs_len;
    u8  *out   = info->async.out;
    u32 *out_len = info->async.out_len;

    ec_key = key;
    ec = EVP_PKEY_get0_EC_KEY(ec_key);

#if OPENSSL_VERSION_NUMBER <= 0x10101005L
    #define sm2_sign_name SM2_do_sign
#else
    #define sm2_sign_name sm2_do_sign

#endif
    extern ECDSA_SIG *sm2_sign_name(const EC_KEY *key,
                           const EVP_MD *digest,
                           const char *user_id, const uint8_t *msg, size_t msg_len);
    sig = sm2_sign_name(ec, EVP_sm3(), "1234567812345678", in, in_len);

    *out_len = i2d_ECDSA_SIG(sig, &out);
    ECDSA_SIG_free(sig);

    return A_TLS_OK;
}

s32 a_crypto_sm2_dec_openssl(void *arg, crypto_info_t *info)
{
    size_t outlen;
    void *key  = info->async.key;
    u8 *in     = info->async.tbs;
    u32 in_len = info->async.tbs_len;
    u8  *out   = info->async.out;
    u32 *out_len = info->async.out_len;

    outlen = A_TLS_PRE_MASTER_KEY_LEN;
#if OPENSSL_VERSION_NUMBER <= 0x10101005L
    #define sm2_dec_name SM2_decrypt
#else
    #define sm2_dec_name sm2_decrypt
#endif
    extern int sm2_dec_name(const EC_KEY *key,
                    const EVP_MD *digest,
                    const uint8_t *ciphertext,
                    size_t ciphertext_len, uint8_t *ptext_buf, size_t *ptext_len);
    if (!sm2_dec_name(EVP_PKEY_get0_EC_KEY(key), EVP_sm3(), in, in_len, out, &outlen))
    {
        return A_TLS_ERR;
    }
    *out_len = outlen;

    return A_TLS_OK;
}

#else
s32 a_crypto_sm2_sign_openssl(void *arg, crypto_info_t *info)
{
    printf("GM SSL need libcrypto.1.1\n");
    return A_TLS_ERR;
}

s32 a_crypto_sm2_dec_openssl(void *arg, crypto_info_t *info)
{
    printf("GM SSL need libcrypto.1.1\n");
    return A_TLS_ERR;
}
#endif

s32 a_crypto_ec_sign_openssl(void *arg, crypto_info_t *info)
{
    EC_KEY *ec;
    EVP_PKEY *ec_key;
    u8 tmp[A_CRYPTO_MAX_MD_LEN];
    a_md_t *md = info->async.md;
    void *key  = info->async.key;
    u8 *in     = info->async.tbs;
    u32 in_len = info->async.tbs_len;
    u8  *out   = info->async.out;
    u32 *out_len = info->async.out_len;

    ec_key = key;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ec = EVP_PKEY_get0_EC_KEY(ec_key);
#else
    ec = ec_key->pkey.ec;
#endif
    if (md) {
        a_md_do_digest(md, in, in_len, tmp);
        in = tmp;
        in_len = md->hash_size;
    }

    if (!ECDSA_sign(EVP_PKEY_EC, in, in_len, out, out_len, ec))
    {
        return A_TLS_ERR;
    }

    return A_TLS_OK;
}

s32 a_crypto_rsa_sign_openssl(void *arg, crypto_info_t *info)
{
    u8 tmp[A_CRYPTO_MAX_MD_LEN];
    u8 encode[512];
    RSA *rsa;
    EVP_PKEY *rsa_key;
    a_md_t *md = info->async.md;
    void *key  = info->async.key;
    u8 *in     = info->async.tbs;
    u32 in_len = info->async.tbs_len;
    u32 mode   = info->async.mode;
    u8  *out   = info->async.out;
    u32 *out_len = info->async.out_len;

    rsa_key = key;

    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
    rsa = EVP_PKEY_get0_RSA(rsa_key);
    #else
    rsa = rsa_key->pkey.rsa;
    #endif
    *out_len = RSA_size(rsa);

    if (md) {
        a_md_do_digest(md, in, in_len, tmp);
        in = tmp;
        in_len = md->hash_size;
    }

#ifdef TLS_DEBUG
    {
                    u32 k;
                    printf("mhash:%d\n",in_len);
                    for(k=0;k<in_len;k++)
                    {
                        printf("%02X", in[k]);
                    }
                    printf("\n");
    }
#endif
    //do padding;
    switch (mode)
    {
        case A_CRYPTO_RSA_PADDING_PSS:
            light_rsa_add_pss_padding(md, in, in_len, encode, *out_len);
            break;
        case A_CRYPTO_RSA_PADDING_PKCS1:
            light_rsa_add_pkcs1_padding(md, in, in_len, encode, *out_len);
            break;
    }
#ifdef TLS_DEBUG
    {
        u32 k;
        printf("rsa in :%d\n",*out_len);
        for(k=0;k<*out_len;k++)
        {
            printf("%02X", encode[k]);
        }
        printf("\n");
    }
#endif
    if (RSA_private_encrypt(*out_len, encode, out, rsa, RSA_NO_PADDING) <= 0)
    {
        return A_TLS_ERR;
    }

    return A_TLS_OK;
}


s32 a_crypto_rsa_dec_openssl(void *arg, crypto_info_t *info)
{
    RSA *rsa;
    EVP_PKEY *rsa_key;
    u8 encode[512];
    u8 *p;
    u32 i = 0;

    void *key  = info->async.key;
    u8 *in     = info->async.tbs;
    u32 in_len = info->async.tbs_len;
    u8  *out   = info->async.out;
    u32 *out_len = info->async.out_len;

    rsa_key = key;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    rsa = EVP_PKEY_get0_RSA(rsa_key);
#else
    rsa = rsa_key->pkey.rsa;
#endif

    if (RSA_private_decrypt(in_len, in, encode, rsa, RSA_NO_PADDING) < 0)
    {
        return A_TLS_ERR;
    }

    /*should be in constant time*/
    p = encode;

    if(*p++ != 0x00
        || *p++ != 0x02)
    {
        return A_TLS_ERR;
    }

    while(p[i] != 0x00)
        i++;

    *out_len = RSA_size(rsa) - i - 3;
    memcpy(out, &p[i + 1], *out_len);

    return A_TLS_OK;
}

void a_tls_init_crypto_env()
{
    u32 i;
    a_cipher_t *cipher, *prev = NULL;
    a_md_t     *md;

    for_each_cipher(cipher) {
        if (prev) {
            prev->next = cipher;
        }

        cipher->cipher = EVP_get_cipherbynid(cipher->openssl_nid);
        cipher->md = a_crypto_find_md(cipher->md_nid);
        prev = cipher;
    }

    for_each_md(md) {
        md->md = EVP_get_digestbynid(md->opentls_nid);
    }

    a_md5    = a_crypto_find_md(A_CRYPTO_NID_MD5);
    a_sha1   = a_crypto_find_md(A_CRYPTO_NID_SHA1);
    a_sha256 = a_crypto_find_md(A_CRYPTO_NID_SHA256);
    a_sha384 = a_crypto_find_md(A_CRYPTO_NID_SHA384);
    a_sha512 = a_crypto_find_md(A_CRYPTO_NID_SHA512);

    for(i = 0; i < sizeof(a_groups)/sizeof(a_group_t); i++)
    {
        a_groups[i].group = EC_GROUP_new_by_curve_name(a_groups[i].openssl_nid);
        if (a_groups[i].group) {
            a_groups[i].field_len = (EC_GROUP_get_degree(a_groups[i].group) + 7) / 8;;
        }
    }

    _a_tls_dec_cbc = a_tls_dec_cbc_openssl;
    _a_tls_enc_cbc = a_tls_enc_cbc_openssl;
    _a_tls_dec_gcm = a_tls_dec_gcm_openssl;
    _a_tls_enc_gcm = a_tls_enc_gcm_openssl;
    _a_tls13_enc_gcm = a_tls13_enc_gcm_openssl;
    _a_tls13_dec_gcm = a_tls13_dec_gcm_openssl;

    _a_crypto_rsa_sign = a_crypto_rsa_sign_openssl;
    _a_crypto_rsa_dec = a_crypto_rsa_dec_openssl;
    _a_crypto_ec_sign = a_crypto_ec_sign_openssl;
    _a_crypto_sm2_sign = a_crypto_sm2_sign_openssl;
    _a_crypto_sm2_dec = a_crypto_sm2_dec_openssl;
    _a_md_proc = a_md_do_digest_openssl;
}

