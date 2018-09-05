#include "a_crypto.h"
#include "a_tls.h"
u8 a_tls_tmp_record_buf[16384];
u8 a_tls_tmp_msg_buf[16384];
u8 a_tls_tmp_ciphertext_buf[16384];
u8 a_tls_tmp_msg_read_buf[16384];
u8 am_cnt[16384] = {0};

/*for TLS 1.2's default sig*/
sigalg_pair_t g_sig_default_single[] =
{
    {
        "rsa_pkcs1_sha1",
        A_TLS_EXT_RSA_SHA1,
        A_CRYPTO_NID_RSA,
        A_CRYPTO_NID_SHA1,
        0,0,
        A_CRYPTO_RSA_PADDING_PKCS1,
        a_crypto_rsa_sign
    },

    {
        "ecdsa_sha1",
        A_TLS_EXT_ECDSA_SHA1,
        A_CRYPTO_NID_EC,
        A_CRYPTO_NID_SHA1,
        0,0,
        0,
        a_crypto_ec_sign
    }
};

/*for < TLS 1.2 or GM*/
sigalg_pair_t g_sig_default[] =
{
    {
        "rsa_pkcs1_md5_sha1",
        0,
        A_CRYPTO_NID_RSA,
        A_CRYPTO_NID_MD5_SHA1,
        0,0,
        A_CRYPTO_RSA_PADDING_PKCS1,
        a_crypto_rsa_sign
    },

    {
        "ecdsa_md5_sha1",
        0,
        A_CRYPTO_NID_EC,
        A_CRYPTO_NID_MD5_SHA1,
        0,0,
        0,
        a_crypto_ec_sign
    },

    {
        "dummy sig",
        0,
        0,
        0,
        0,0,
        0,
        0
    },

    {
        "sm2_with_sm3",
        0,
        A_CRYPTO_NID_SM,
        A_CRYPTO_NID_SM3,
        0,0,
        0,
        a_crypto_sm2_sign
    }
};

/*For client supporting sig_alg*/
sigalg_pair_t g_sigalg_pair[A_TLS_MAX_SIG_ALG] =
{
    /*sentinel*/
    {   0,
        0,
        0,
        0,
        0,0,
        0,
        0
    },

    {
        "rsa_pss_rsae_sha256",
        A_TLS_RSAPSS_RSAE_SHA256,
        A_CRYPTO_NID_RSA,
        A_CRYPTO_NID_SHA256,
        0,1,
        A_CRYPTO_RSA_PADDING_PSS,
        a_crypto_rsa_sign
    },

    {
        "rsa_pss_rsae_sha384",
        A_TLS_RSAPSS_RSAE_SHA384,
        A_CRYPTO_NID_RSA,
        A_CRYPTO_NID_SHA384,
        0,1,
        A_CRYPTO_RSA_PADDING_PSS,
        a_crypto_rsa_sign
    },

    {
        "rsa_pss_rsae_sha512",
        A_TLS_RSAPSS_RSAE_SHA512,
        A_CRYPTO_NID_RSA,
        A_CRYPTO_NID_SHA512,
        0,1,
        A_CRYPTO_RSA_PADDING_PSS,
        a_crypto_rsa_sign
    },

    {
        "ecdsa_secp256r1_sha256",
        A_TLS_ECDSA_256,
        A_CRYPTO_NID_EC,
        A_CRYPTO_NID_SHA256,
        NID_X9_62_prime256v1,1,
        0,
        a_crypto_ec_sign
    },

    {
        "ecdsa_secp384r1_sha384",
        A_TLS_ECDSA_384,
        A_CRYPTO_NID_EC,
        A_CRYPTO_NID_SHA384,
        NID_secp384r1,1,
        0,
        a_crypto_ec_sign
    },

    {
        "ecdsa_secp521r1_sha512",
        A_TLS_ECDSA_512,
        A_CRYPTO_NID_EC,
        A_CRYPTO_NID_SHA512,
        NID_secp521r1,1,
        0,
        a_crypto_ec_sign
    },
#ifdef NID_X25519
    {
        "ed25519",
        A_TLS_ED25519,
        A_CRYPTO_NID_EC,
        0,
        NID_X25519,1,
        0,
        a_crypto_ec_sign
    },
#endif
#ifdef NID_X448
    {
        "ed448",
        A_TLS_ED448,
        A_CRYPTO_NID_EC,
        0,
        NID_X448,1,
        0,
        a_crypto_ec_sign
    },
#endif

    /*old*/
    {
        "rsa_pkcs1_sha1",
        A_TLS_EXT_RSA_SHA1,
        A_CRYPTO_NID_RSA,
        A_CRYPTO_NID_SHA1,
        0,0,
        A_CRYPTO_RSA_PADDING_PKCS1,
        a_crypto_rsa_sign
    },

    {
        "rsa_pkcs1_sha256",
        A_TLS_EXT_RSA_SHA256,
        A_CRYPTO_NID_RSA,
        A_CRYPTO_NID_SHA256,
        0,0,
        A_CRYPTO_RSA_PADDING_PKCS1,
        a_crypto_rsa_sign
    },

    {
        "rsa_pkcs1_sha384",
        A_TLS_EXT_RSA_SHA384,
        A_CRYPTO_NID_RSA,
        A_CRYPTO_NID_SHA384,
        0,0,
        A_CRYPTO_RSA_PADDING_PKCS1,
        a_crypto_rsa_sign
    },

    {
        "rsa_pkcs1_sha512",
        A_TLS_EXT_RSA_SHA512,
        A_CRYPTO_NID_RSA,
        A_CRYPTO_NID_SHA512,
        0,0,
        A_CRYPTO_RSA_PADDING_PKCS1,
        a_crypto_rsa_sign
    },

    {
        "ecdsa_sha1",
        A_TLS_EXT_ECDSA_SHA1,
        A_CRYPTO_NID_EC,
        A_CRYPTO_NID_SHA1,
        0,0,
        0,
        a_crypto_ec_sign
    },

    {
        "ecdsa_sha256",
        A_TLS_EXT_ECDSA_SHA256,
        A_CRYPTO_NID_EC,
        A_CRYPTO_NID_SHA256,
        0,0,
        0,
        a_crypto_ec_sign
    },

    {
        "ecdsa_sha256",
        A_TLS_EXT_ECDSA_SHA384,
        A_CRYPTO_NID_EC,
        A_CRYPTO_NID_SHA384,
        0,0,
        0,
        a_crypto_ec_sign
    },

    {
        "ecdsa_sha512",
        A_TLS_EXT_ECDSA_SHA512,
        A_CRYPTO_NID_EC,
        A_CRYPTO_NID_SHA512,
        0,0,
        0,
        a_crypto_ec_sign
    },
};

void *a_tls_malloc(unsigned long size)
{
    am_head_t *head;
    u8 *p;

    p = malloc(sizeof(am_head_t) + size);
    if (p == NULL) {
        return NULL;
    }

    head = (am_head_t*)p;
    head->size = size;
    am_cnt[size&0x3FFF]++;

    return p + sizeof(am_head_t);
}

void a_tls_free(void *p)
{
    am_head_t *head;
    u8 *ptr = p;

    ptr -= sizeof(am_head_t);

    head = (am_head_t*)ptr;
    am_cnt[head->size&0x3FFF]--;

    free(ptr);
}

s32 a_tls_gen_tls_hmac(a_md_t *md, u8 *key, u8 *add, u32 add_len, u8 *data, u32 data_len, u8 *out)
{
    u32 out_len;
    s32 ret = A_TLS_OK;

#ifdef TLS_DEBUG
    {
        int k;
        printf("hmac head:%d\n",13);
        for(k=0;(u32)k<13;k++) {
            printf("%x ",add[k]);
        }
        printf("\n");
    }

    {
        int k;
        printf("hmac data:%d\n",data_len);
        for(k=0;(u32)k<data_len;k++) {
            printf("%x ",data[k]);
        }
        printf("\n");
    }
    {
        int k;
        printf("hmac key:%d\n",md->hash_size);
        for(k=0;(u32)k<md->hash_size;k++) {
            printf("%x ",key[k]);
        }
        printf("\n");
    }
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    HMAC_CTX *ctx =  HMAC_CTX_new();
#else
    HMAC_CTX ctxt;
    HMAC_CTX *ctx;

    HMAC_CTX_init(&ctxt);
    ctx = &ctxt;
#endif
    if(ctx == NULL
        || !HMAC_Init_ex(ctx, key, md->hash_size, md->md, NULL)
        || !HMAC_Update(ctx, add, add_len)
        || !HMAC_Update(ctx, data, data_len)
        || !HMAC_Final(ctx, out, &out_len))
    {
        ret = A_TLS_ERR;
    }
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    HMAC_CTX_free(ctx);
#else
    HMAC_CTX_cleanup(ctx);
#endif
    return ret;
}

void a_tls_prf(a_tls_t *tls, u8 *buf, u32 buf_len, u8 *sec, u32 sec_len, u8 *out1, u8 *out2, u32 olen)
{
    u32 i;
    u16 version = tls->handshake_version;

    if (IS_TLSGM(tls)) {
        a_crypto_phash(tls->sess->md, sec, sec_len, buf, buf_len, out1, olen);
        return;
    }

    if (version == A_TLS_TLS_1_2_VERSION) {

        if(A_CRYPTO_NID_SHA384 == tls->sess->md->nid) {
            a_crypto_phash(tls->sess->md, sec, sec_len, buf, buf_len, out1, olen);

        } else {
            a_crypto_phash(a_sha256, sec, sec_len, buf, buf_len, out1, olen);
        }

    } else {
        u8 *S1,*S2;
        u32 len;
        len=sec_len/2;
        S1=sec;
        S2= &(sec[len]);
        len+=(sec_len&1); /* add for odd, make longer */

        a_crypto_phash(a_md5, S1, len, buf, buf_len, out1, olen);

        a_crypto_phash(a_sha1, S2, len, buf, buf_len, out2, olen);

        for (i = 0; i < olen; i++) {
            out1[i] ^= out2[i];
        }
    }
}

s32 a_tls_gen_master_secret(a_tls_t *tls, u8 *pms, u32 pms_len)
{
    u8 buf[A_TLS_MASTER_KEY_BUF_LEN], buf_tmp[A_TLS_MASTER_KEY_BUF_LEN];
    u8 *p;

    memset(buf, 0, A_TLS_MASTER_KEY_BUF_LEN);
    memset(buf_tmp, 0, A_TLS_MASTER_KEY_BUF_LEN);
    p = buf;

    memcpy(p, A_TLS_MASTER_SECRET_CONST, A_TLS_MASTER_SECRET_CONST_LEN);
    p += A_TLS_MASTER_SECRET_CONST_LEN;

    memcpy(p, tls->handshake->clnt_random, A_TLS_RAND_SIZE);
    p += A_TLS_RAND_SIZE;

    memcpy(p, tls->handshake->srv_random, A_TLS_RAND_SIZE);
    memset(tls->sess->master_secret, 0, sizeof(tls->sess->master_secret));

    a_tls_prf(tls, buf, sizeof(buf), pms, pms_len, tls->sess->master_secret, buf_tmp, A_TLS_MASTER_KEY_LEN);

    return A_TLS_OK;

}

s32 a_tls_get_sigalg_index(u32 nid)
{
    u32 i;
    for (i = 0; i < sizeof(g_sigalg_pair)/sizeof(sigalg_pair_t); i++)
    {
        if (g_sigalg_pair[i].tls_id == nid)
        {
            return i;
        }
    }
    return -1;
}

sigalg_pair_t * a_tls_select_sigalg(a_tls_t *tls, void **key, a_md_t **md)
{
    sigalg_pair_t *ret = NULL;
    u32 sign = tls->sess->cipher->sign;
    u32 index = sign;

    /*we have selected the sig alg from client's ext*/
    ret = tls->sig;
    if (ret) {
        goto end;
    }

    if (tls->version == A_TLS_TLS_1_2_VERSION
        || sign == A_CRYPTO_NID_EC)
    {
        ret = &g_sig_default_single[index];

    } else {

        ret = &g_sig_default[index];
    }
end:
    if (md) {
        *md = a_crypto_find_md(ret->md_nid);
    }

    if (key) {
        *key = tls->cfg->pkey[index];
    }

    return ret;
}
s32 a_tls_do_read(a_tls_t *tls, u8 *data, s32 data_len)
{
    return recv(tls->fd, data, data_len, 0);
}

s32 a_tls_do_write(a_tls_t *tls, u8 *data, s32 data_len, s32 *written)
{
    s32 nsend;
    u8 *p = data;

    *written = 0;

    nsend = send(tls->fd, p, data_len, 0);
    if (nsend > 0) {
        *written = nsend;
        return A_TLS_OK;

    } else {
        if (errno == EAGAIN) {
            return A_TLS_WANT_WRITE;
        }
        a_tls_error(tls, "a_tls_do_write err errno:%d", errno);
        return A_TLS_ERR;
    }
}

s32 a_tls_write_internal(a_tls_t *tls, u8 *data, s32 data_len)
{
    s32 ret, written;

#ifdef TLS_DEBUG
    printf("internal try write:%d\n",data_len);
#endif
    for (;;) {
        ret = a_tls_do_write(tls, data, data_len, &written);
        if (ret == A_TLS_OK) {

            if (written < data_len) {
                data += written;
                data_len -= written;
                /*try write again*/
                continue;
            }
            return A_TLS_OK;
        }
        //may be want write
        break;
    }

    if (ret == A_TLS_WANT_WRITE) {
        tls->nbio = a_tls_buf_new(data_len);
        if (tls->nbio == NULL) {
            a_tls_error(tls, "tls new write bio err");
            return A_TLS_ERR;
        }
        tls->nbio->last = memcpy(tls->nbio->last, data, data_len);
        tls->nbio_state = tls->state;
        tls->state = A_TLS_STATE_WRITTING;
        return A_TLS_WANT_WRITE;
    }

    a_tls_error(tls, "a_tls_write_internal err");
    return A_TLS_ERR;
}

s32 a_tls_nbio_flush(a_tls_t *tls)
{
    s32 ret, tosend, written;

    tosend = tls->nbio->last - tls->nbio->pos;

    ret = a_tls_do_write(tls, tls->nbio->pos, tosend, &written);
    if (ret == A_TLS_OK) {
        a_tls_buf_free(tls->nbio);
        tls->nbio = NULL;
        tls->state = tls->nbio_state;
        return A_TLS_CONTINUE;
    }

    if (ret == A_TLS_WANT_WRITE) {
        tls->nbio->pos += written;
        return A_TLS_WANT_WRITE;
    }

    a_tls_error(tls, "a_tls_nbio_flush err");
    return A_TLS_ERR;
}

s32 a_tls_get_hs_digest(a_tls_t *tls, u8 *out, u32 *out_len)
{
    a_cipher_t *cipher = tls->sess->cipher;
    a_md_t *md = cipher->md;

    a_md_do_digest(md,
        tls->handshake->diget_cache,
        tls->handshake->diget_off,
        out);

    *out_len = md->hash_size;
    return A_TLS_OK;
}

s32 a_tls_get_hs_data(a_tls_t *tls, u8 **out, u32 *out_len)
{
    *out = tls->handshake->diget_cache;
    *out_len = tls->handshake->diget_off;
    return A_TLS_OK;
}

void a_tls_free_hs(a_tls_handshake_t *hs)
{
    if (hs->key_block) {
        a_tls_free(hs->key_block);
    }

    if (hs->peer_ecdh_pub) {
        a_tls_free(hs->peer_ecdh_pub);
    }

    if (hs->self_ecdh_pub) {
        a_tls_free(hs->self_ecdh_pub);
    }

    if (hs->self_ecdh_prv) {
        a_tls_free(hs->self_ecdh_prv);
    }

    if (hs->diget_cache) {
        a_tls_free(hs->diget_cache);
    }

    if (hs->self_pkey) {
        EVP_PKEY_free(hs->self_pkey);
    }

    if (hs->peer_pkey) {
        EVP_PKEY_free(hs->peer_pkey);
    }

    if (hs->sni) {
        a_tls_free(hs->sni);
    }

    a_tls_free(hs);
}

s32 a_tls_save_hs(a_tls_t *tls, u8 *data, s32 data_len)
{
    a_tls_handshake_t *hs = tls->handshake;
    u32 max_size = hs->diget_len;
    u32 use_len = hs->diget_off;
    u8 *new_digest_cache = NULL;

    if(unlikely(use_len + data_len > max_size)) {
        max_size += (data_len + 2048) & (~(2048 - 1));
        new_digest_cache = a_tls_malloc(max_size);
        if (new_digest_cache == NULL) {
            a_tls_error(tls, "tls realloc digest err");
            return A_TLS_ERR;
        }
        memcpy(new_digest_cache, hs->diget_cache, hs->diget_off);
        a_tls_free(hs->diget_cache);

        hs->diget_cache = new_digest_cache;
        hs->diget_len = max_size;
    }

    memcpy(hs->diget_cache + use_len, data, data_len);
    hs->diget_off += data_len;
    return A_TLS_OK;
}

s32 a_tls_snd_msg(a_tls_t *tls, u8 *data, s32 data_len, u8 type)
{
    s32 tosend;
    u8 *p = a_tls_tmp_record_buf;

    if (type == A_TLS_RT_HANDHSHAKE
        && a_tls_save_hs(tls, data, data_len) != A_TLS_OK)
    {
        a_tls_error(tls, "tls save hs msg err %d", data_len);
        return A_TLS_ERR;
    }

    /*if encryption is needed*/
    if (type != A_TLS_RT_CCS
        && tls->write_ctx)
    {
        crypto_info_t info;
        info.p = data;
        info.p_len = data_len;
        info.type = type;
        if (tls->spec->enc(tls, &info) != A_TLS_OK) {
            a_tls_error(tls, "tls enc err");
            return A_TLS_ERR;
        }

        data = info.c;
        data_len = info.c_len;

        if (IS_TLS13(tls)) {
            type = A_TLS_RT_APPLICATION_DATA;
        }
    }

    *p++ = type;
    s2n(tls->handshake_version, p);
    s2n(data_len, p);
    memcpy(p, data, data_len);
    p += data_len;
    tosend = (s32)(p - a_tls_tmp_record_buf);
    return a_tls_write_internal(tls, a_tls_tmp_record_buf, tosend);
}

s32 a_tls_get_message(a_tls_t *tls, msg_t *msg, s32 type)
{
    crypto_info_t crypto_info;
    s32 toread, nread, alert;
    u8 *read_buf, *start_buf = NULL;
    u32 *ref_len;
    static u8 ccs = 0x01;

    alert = 0;

restart:
    if (tls->read_state == A_TLS_READ_HEAD) {
        toread = A_TLS_HEAD_LEN - tls->cache_len;
        read_buf = tls->cache + tls->cache_len;
        tls->body_len = 0;
        tls->body_read = 0;
        ref_len = &tls->cache_len;

    } else {

        /*try to save into tmp buf first*/
        if (!tls->body_read) {
            read_buf = a_tls_tmp_msg_read_buf;
            start_buf = read_buf;

        } else {
            read_buf = tls->buf + tls->body_read;
            start_buf = tls->buf;
        }

        toread = tls->body_len - tls->body_read;
        ref_len = &tls->body_read;
    }

    nread = a_tls_do_read(tls, read_buf, toread);
#ifdef TLS_DEBUG
    printf("a_tls_get_message :%d\n", nread);
#endif
    if (nread == 0) {
        /*peer close*/
        return A_TLS_READ_FIN;
    } else if (nread < 0) {
        if (errno == EAGAIN) {
            return A_TLS_WANT_READ;
        }
        a_tls_error(tls, "tls get message err errno:%d", errno);
        return A_TLS_ERR;
    }

    if (nread < toread) {

        if (tls->read_state == A_TLS_READ_BODY
            && !tls->body_read) {

            tls->buf = a_tls_malloc(16384);
            if (tls->buf == NULL) {
                return A_TLS_ERR;
            }
            memcpy(tls->buf, start_buf, nread);
        }

        *ref_len += nread;
        return A_TLS_WANT_READ;
    }

    /*The len is what we want*/
    if (tls->read_state == A_TLS_READ_HEAD) {
        u8 *pos = tls->cache;
        u16 version;
        if (*pos != A_TLS_RT_CCS
            && *pos != A_TLS_RT_ALERT
            && *pos != A_TLS_RT_HANDHSHAKE
            && *pos != A_TLS_RT_APPLICATION_DATA)
        {
            a_tls_error(tls, "tls get record type err:%d", *pos);
            return A_TLS_ERR;
        }

        if (*pos++ == A_TLS_RT_ALERT) {
            alert = 1;
            type  = A_TLS_RT_ALERT;
        }

        n2s(pos, version);

        if (version != A_TLS_TLS_1_0_VERSION
            && version != A_TLS_TLS_1_1_VERSION
            && version != A_TLS_TLS_1_2_VERSION
            && version != A_TLS_TLS_1_2_VERSION
            && version != A_TLS_GM_VERSION)
        {
            a_tls_error(tls, "tls get record version err:%d", version);
            return A_TLS_ERR;
        }

        n2s(pos, tls->body_len);

        tls->read_state = A_TLS_READ_BODY;

        if(type == A_TLS_RT_CCS
            && tls->cache[0] != A_TLS_RT_CCS)
        {
            /*TLS13 peer may not send ccs, so we construct a fake one*/
            if (IS_TLS13(tls)) {
                msg->data   = &ccs;
                msg->len    = 1;
                msg->rt_type= A_TLS_RT_CCS;
                return A_TLS_OK;

            } else {
                a_tls_error(tls, "tls get expected ccs err:%d", tls->cache[0]);
                return A_TLS_ERR;
            }
        }
        goto restart;
    }

    if (tls->buf) {
        start_buf = a_tls_tmp_msg_read_buf;
        memcpy(a_tls_tmp_msg_read_buf, tls->buf, tls->body_len);
        a_tls_free(tls->buf);
        tls->buf = NULL;
    }

    tls->read_state = A_TLS_READ_HEAD;

    /*ccs should not be decrypted*/
    if (type == A_TLS_RT_CCS
        && tls->cache[0] == A_TLS_RT_CCS)
    {
        msg->data   = start_buf;
        msg->len    = tls->body_len;
        msg->rt_type= A_TLS_RT_CCS;
        return A_TLS_OK;
    }

    if (tls->read_ctx) {
        crypto_info.p       = start_buf;
        crypto_info.c       = start_buf;
        crypto_info.p_len   = tls->body_len;
        crypto_info.c_len   = tls->body_len;
        crypto_info.type    = type;

        if (tls->spec->dec(tls, &crypto_info)
            == A_TLS_ERR)
        {
            /*If we don't accept early data but client has alredy sent it.
            * We should ignore it and reset cipher context.
            */
            if (tls->ext.early_data == A_TLS_EARLY_DATA_REJECT) {
                //TO DO, we need count early data
                memset(tls->seq[0], 0 ,8);
                goto restart;
            }
            a_tls_error(tls, "tls get bad message err");
            return A_TLS_ERR;
        }

        msg->data   = crypto_info.p;
        msg->len    = crypto_info.p_len;
        msg->rt_type= crypto_info.type;

    } else {
        msg->data   = start_buf;
        msg->len    = tls->body_len;
        msg->rt_type= tls->cache[0];
    }

    if (alert) {

        if (msg->len != 2) {
            return A_TLS_ERR;
        }

        /*TODO parse the alert number*/
        a_tls_error(tls, "tls get alert code:%02x %02x", msg->data[0], msg->data[1]);
        return A_TLS_READ_FIN;
    }

    return A_TLS_OK;
}

s32 a_tls_change_cipher(a_tls_t *tls, u32 flag)
{
    return tls->spec->change_cipher(tls, flag);
}

s32 a_tls_init(a_tls_t *tls)
{
    tls->handshake = a_tls_malloc(sizeof(a_tls_handshake_t));
    if (tls->handshake == NULL) {
        a_tls_free_tls(tls);
        return A_TLS_ERR;
    }

    memset(tls->handshake, 0, sizeof(a_tls_handshake_t));

    tls->handshake->diget_cache = a_tls_malloc(8192);
    if (tls->handshake->diget_cache == NULL) {
        a_tls_free_tls(tls);
        return A_TLS_ERR;
    }

    tls->handshake->diget_len = 8192;

    tls->dir   = 1;/*server*/
    tls->state = A_TLS_STATE_GET_CLNT_HELLO;
    return A_TLS_OK;
}

s32 a_tls_handshake(a_tls_t *tls)
{

    s32 ret;

#ifdef TLS_DEBUG
    printf("a_tls_handshake start state:%d\n",tls->state);
#endif
    for (;;) {
        ret = tls->state_proc[tls->state](tls);
#ifdef TLS_DEBUG
        printf("tls_state_proc ret:%d end state:%d\n",ret, tls->state);
#endif
        if (ret != A_TLS_OK) {
            return ret;
        }

        if (tls->state == A_TLS_STATE_ESTABLISH) {
            if (tls->handshake) {
                a_tls_free_hs(tls->handshake);
                tls->handshake = NULL;
            }
            return A_TLS_OK;
        }
    }

    return A_TLS_ERR;
}

a_tls_buf_t *a_tls_buf_new(unsigned long size)
{
    a_tls_buf_t *ret = a_tls_malloc(sizeof(a_tls_buf_t) + size);
    if (ret == NULL) {
        return NULL;
    }

    ret->pos  = ret->start;
    ret->last = ret->start;
    ret->end  = ret->start + size;
    return ret;
}

a_tls_buf_t *a_tls_buf_expand(a_tls_buf_t *old, unsigned long add)
{
    a_tls_buf_t *new;
    unsigned long old_size = old->end - old->start;
    unsigned long old_pos  = old->pos - old->start;

    if (old_size + add < old_size) {
        //overflow
        return NULL;
    }

    new = a_tls_malloc(old_size + add);
    if (new == NULL) {
        return NULL;
    }

    new->pos  = new->start + old_pos;
    new->last = new->start;
    new->end  = new->start + old_size + add;

    new->last = memcpy(new->last, old->start, old_pos);
    new->last += old_pos;

    return new;
}

void a_tls_buf_free(a_tls_buf_t *ret)
{
    a_tls_free(ret);
}

s32 a_tls_sess_new(a_tls_t *tls)
{
    a_tls_sess_t *sess;

    sess = a_tls_malloc(sizeof(a_tls_sess_t));
    if (NULL == sess) {
        a_tls_error(tls, "tls sess new err");
        return A_TLS_ERR;
    }

    memset(sess, 0, sizeof(a_tls_sess_t));
    sess->sni = tls->handshake->sni;
    sess->sni_len = tls->handshake->sni_len;
    tls->handshake->sni = NULL;
    tls->handshake->sni_len = 0;
    tls->sess = sess;
    return A_TLS_OK;
}

s32 a_tls_check_and_set_curve(a_tls_t *tls, sigalg_pair_t *sig)
{
    u8 i = 0, index;
    a_group_t *group;

    for (;;) {

        index = tls->handshake->clnt_curve[i++];
        if (index == 0) {
            a_tls_error(tls, "check clnt_curve err");
            return A_TLS_ERR;
        }

        group = a_crypto_get_group_by_index(index);
        if (group == NULL) {
            continue;
        }

        if (sig->curve/*Sig specify the curve type*/
            && group->openssl_nid != sig->curve)
        {
            continue;
        }

        tls->support_gp = group;
        return A_TLS_OK;
    }

    return A_TLS_ERR;
}

s32 a_tls_check_and_set_sig(a_tls_t *tls, a_cipher_t *cipher)
{
    sigalg_pair_t *sig;
    u8 i = 0, index;

#ifdef TLS_DEBUG
    printf("checking cipher %s\n",cipher->name);
#endif
    for (;;) {

        index = tls->handshake->clnt_sig[i++];
        if (index == 0) {
            a_tls_error(tls, "check clnt_sig err");
            return A_TLS_ERR;
        }

        sig = &g_sigalg_pair[index];
        if (sig == NULL) {
            continue;
        }
#ifdef TLS_DEBUG
        printf("------checking sig %s\n",sig->name);
#endif

        if (cipher->sign != sig->pkey) {
            continue;
        }

        if (IS_TLS13(tls)) {
            if (sig->pkey == A_CRYPTO_NID_RSA
                && sig->pkey != A_CRYPTO_RSA_PADDING_PSS)
            {
                continue;
            }
        }

        /*The curve of sig_alg should match the cert's curve*/
        if (tls->cfg->curve
            && sig->curve
            && tls->cfg->curve != sig->curve) {
            continue;
        }

        if (sig->pkey == A_CRYPTO_NID_EC
            && a_tls_check_and_set_curve(tls, sig) != A_TLS_OK) {
            continue;
        }

        tls->sig = sig;
        return A_TLS_OK;
    }

    return A_TLS_ERR;
}
s32 a_tls_check_cipher(a_tls_t *tls, a_cipher_t *cipher)
{
    /*check the version*/
    if ((tls->version == A_TLS_TLS_1_0_VERSION
            && !(cipher->flag&A_CRYPTO_CIPHER_TLS1))
        || (tls->version == A_TLS_TLS_1_1_VERSION
            && !(cipher->flag&A_CRYPTO_CIPHER_TLS1_1))
        || (tls->version == A_TLS_TLS_1_2_VERSION
            && !(cipher->flag&A_CRYPTO_CIPHER_TLS1_2))
        || (tls->version == A_TLS_TLS_1_3_VERSION
            && !(cipher->flag&A_CRYPTO_CIPHER_TLS1_3))
        || (tls->version == A_TLS_GM_VERSION
            && !(cipher->flag&A_CRYPTO_CIPHER_SM)))
    {
        return A_TLS_ERR;
    }

    /*TLS1.3's cipher doesn't contain signature info*/
    if (IS_TLS13(tls)) {
        return A_TLS_OK;
    }

    if (cipher->flag&A_CRYPTO_CIPHER_ECDHE
        && (((!tls->cfg->pkey[A_CRYPTO_NID_EC]) && (cipher->sign == A_CRYPTO_NID_EC))
          || ((!tls->cfg->pkey[A_CRYPTO_NID_RSA]) && (cipher->sign == A_CRYPTO_NID_RSA))))
    {
        return A_TLS_ERR;
    }

    if (cipher->flag&A_CRYPTO_CIPHER_RSA
        && (!tls->cfg->pkey[A_CRYPTO_NID_RSA] || !tls->cfg->cert[A_CRYPTO_NID_RSA]))
    {
        return A_TLS_ERR;
    }

    return A_TLS_OK;
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
s32 a_tls_process_cke_ecc(void *arg, u8 *in, u32 in_len)
{
    s32 ret;
    u8  pms[A_TLS_PRE_MASTER_KEY_LEN];
    u32 pms_len;
    crypto_info_t info;
    a_tls_t *tls = arg;
    u8      *p = in;
    void    *key;

    n2s(p, pms_len);
    if (pms_len != in_len - 2) {
        a_tls_error(tls, "tls gm ecc len err pms_len1:%d", pms_len);
        return A_TLS_ERR;
    }

    key = tls->cfg->pkey[A_CRYPTO_NID_SM];

    info.async.key = key;
    info.async.tbs = p;
    info.async.tbs_len = pms_len;
    info.async.out = pms;
    info.async.out_len = &pms_len;

    ret = a_crypto_sm2_dec(NULL, &info);
    if (ret != A_TLS_OK) {
        return ret;
    }

    if(unlikely(A_TLS_PRE_MASTER_KEY_LEN != pms_len)) {
        a_tls_error(tls, "tls gm ecc len err pms_len2:%d", pms_len);
        return A_TLS_ERR;
    }

    return a_tls_gen_master_secret(tls, pms, pms_len);
}
#else
s32 a_tls_process_cke_ecc(void *arg, u8 *in, u32 in_len)
{
    printf("GM SSL need libcrypto.1.1\n");
    return A_TLS_ERR;
}
#endif
s32 a_tls_process_cke_rsa(void *arg, u8 *in, u32 in_len)
{
    crypto_info_t info;
    a_tls_t *tls = arg;
    u8 *p = in;
    u8 pms[A_TLS_PRE_MASTER_KEY_LEN];
    u32 pms_len;
    void *key;

    n2s(p, pms_len);

    if (pms_len != in_len - 2) {
        a_tls_error(tls, "tls rsa len err pms_len:%d", pms_len);
        return A_TLS_ERR;
    }

    key = tls->cfg->pkey[A_CRYPTO_NID_RSA];

    info.async.key = key;
    info.async.tbs = p;
    info.async.tbs_len = pms_len;
    info.async.out = pms;
    info.async.out_len = &pms_len;

    if (a_crypto_rsa_dec(NULL, &info) != A_TLS_OK
        || pms_len != A_TLS_PRE_MASTER_KEY_LEN)
    {
        a_tls_error(tls, "tls rsa dec err");
        return A_TLS_ERR;
    }

    return a_tls_gen_master_secret(tls, pms, pms_len);
}

s32 a_tls_process_cke_ecdh(void *arg, u8 *in, u32 in_len)
{
    u32 pms_len;
    u8 *p = in, pms[A_CRYPTO_MAX_EC_PUB_LEN/2];
    a_tls_t *tls = arg;
    a_tls_handshake_t *hs = tls->handshake;

    in_len -= 1;

    if (*p++ != in_len) {
        a_tls_error(tls, "tls ecdhe len dec err:%d", in_len);
        return A_TLS_ERR;
    }

    a_crypto_calc_ec_shared(tls->support_gp,
        hs->self_ecdh_prv,
        hs->self_ecdh_prv_len,
        p,
        in_len,
        pms, &pms_len);
#ifdef TLS_DEBUG
    {
        u32 k;
        printf("ecdhe pms %d\n",pms_len);
        for(k=0;k<pms_len;k++)
            printf("%02X",pms[k]);
        printf("\n");
    }
#endif
    a_tls_gen_master_secret(tls, pms, pms_len);
#ifdef TLS_DEBUG
    {
        u32 k;
        printf("master key:%d\n",A_TLS_MASTER_KEY_LEN);
        for(k=0;k<A_TLS_MASTER_KEY_LEN;k++)
            printf("%02X",tls->sess->master_secret[k]);
        printf("\n");
    }
#endif

    return A_TLS_OK;
}

s32 a_tls_construct_srv_hello(a_tls_t *tls,  u8 *buf)
{
    u8 *p = buf;

    s2n(tls->handshake_version, p);
    memcpy(p ,tls->handshake->srv_random, A_TLS_RAND_SIZE);
    p += A_TLS_RAND_SIZE;

    /*RFC:
      1: pre-TLS1.3 resume
      2: TLS1.3 simple echo
    */
    if (IS_TLS13(tls)
        || tls->hit)
    {
        *p++ = A_TLS_SESS_ID_SIZE;
        memcpy(p, tls->handshake->session_id, A_TLS_SESS_ID_SIZE);
        p += A_TLS_SESS_ID_SIZE;

    } else {
        /*only session ticket support*/
        *p++ = 0;
    }

    /*cipher suit*/
    s2n(tls->sess->cipher->tls_nid, p);

    /*compress*/
    *p++ = 0;
    return (s32)(p - buf);
}

s32 a_tls_cipher_get(a_tls_t *tls, u8 *ciphers, u32 ciphers_len)
{
    u8 *p = ciphers;
    u16 cipher_nid;
    a_cipher_t *c;

    if (ciphers_len&1) {
        a_tls_error(tls, "tls ciphers len err:%d", ciphers_len);
        return A_TLS_ERR;
    }

    if (tls->cfg->srv_prefer) {

        c = tls->cfg->cipers;

        while (c) {
            u32 tmp_len = ciphers_len;
            p = ciphers;

            if(a_tls_check_cipher(tls, c) != A_TLS_OK
                || c->md == NULL) {
                c = c->next;
                continue;
            }

            /*whether the client's sig_algs are compatible for this cipher*/
            if (tls->handshake->clnt_sig[0] != 0
                && a_tls_check_and_set_sig(tls, c) != A_TLS_OK) {
                continue;
            }

            while(tmp_len) {
                n2s(p, cipher_nid);
                if (cipher_nid == c->tls_nid) {
                    break;
                }
                tmp_len -= 2;
            }

            if (tmp_len == 0) {
                c = c->next;
                continue;
            }

            tls->sess->cipher   = c;
            tls->sess->md       = c->md;
            return A_TLS_OK;

        }

        a_tls_error(tls, "tls ciphers find err");
        return A_TLS_ERR;
    }

    while(ciphers_len) {
        n2s(p, cipher_nid);
        ciphers_len -= 2;

        if ((c = a_crypto_find_cipher_by_nid(cipher_nid)) != NULL
            && (a_tls_check_cipher(tls, c) == A_TLS_OK)
            && c->md != NULL)
        {
            /*if the client's sig_algs are compatible for this cipher*/
            if (tls->handshake->clnt_sig[0] != 0
                && a_tls_check_and_set_sig(tls, c) != A_TLS_OK) {
                continue;
            }

            tls->sess->cipher   = c;
            tls->sess->md       = c->md;
            return A_TLS_OK;
        }
    }

    a_tls_error(tls, "tls ciphers find err");
    return A_TLS_ERR;
}

s32 a_tls_process_clnt_hello(a_tls_t *tls, msg_t *msg)
{
    u8 *p, *ciphers;
    s32 len, ciphers_len, ext_len;
    u16 version;

    p = msg->data;

    if (*p++ != A_TLS_MT_CLNT_HELLO) {
        /*Not client hello message*/
        a_tls_error(tls, "tls clnt_hello type err");
        return A_TLS_ERR;
    }

    n2l3(p, len);

    /*client hello must monopolize the record totally*/
    if (msg->data + msg->len != p + len) {
        a_tls_error(tls, "tls clnt_hello len err msg->len:%d, len:%d", msg->len, len);
        return A_TLS_ERR;
    }

    n2s(p, version);
    tls->handshake->clnt_version = version;

    memcpy(tls->handshake->clnt_random, p, 32);
    p += 32;

    /*session id len*/
    len = *p++;
    memcpy(tls->handshake->session_id, p, len);
    p += len;

    n2s(p, ciphers_len);
    ciphers = p;

    (void)ciphers;
    p += ciphers_len;

    /*compress*/
    len = *p++;
    p += len;

    /*extension exist*/
    if(likely(p + 2 <= msg->data + msg->len)) {
        n2s(p, ext_len);
        a_tls_parse_extension(tls, p, ext_len);
        p += ext_len;

    } else {
        tls->ext.no_ext = 1;
    }

    if (tls->sess == NULL) {
        if (A_TLS_OK != a_tls_sess_new(tls)) {
            return A_TLS_ERR;
        }

    } else {
        tls->hit = 1;

        if (tls->sess->sni_len != tls->handshake->sni_len
            || memcmp(tls->sess->sni, tls->handshake->sni, tls->sess->sni_len))
        {
            a_tls_error(tls, "The sni in hello doesn't match the sni in ticket");
            return A_TLS_ERR;
        }
    }

    if (a_tls_check_version(tls, version) != A_TLS_OK) {
        return A_TLS_ERR;
    }

    /*now we have select a version*/
    if (a_tls_cipher_get(tls, ciphers, ciphers_len)
        != A_TLS_OK)
    {
        a_tls_error(tls, "tls a_tls_cipher_get err");
        return A_TLS_ERR;
    }

    /*need select a certificate by the cipher which we have selected*/
    tls->selected_cert = tls->sess->cipher->sign;

    return A_TLS_OK;
}

s32 a_tls_check_version(a_tls_t *tls, u16 version)
{
    /*Done in suport_version*/
    if (IS_TLS13(tls)) {
        tls->flag = A_TLS_1_3;
        return A_TLS_OK;
    }

    if (IS_TLSGM(tls)
        && !tls->cfg->gm_support) {
        a_tls_error(tls, "tls recv GMSSL but are not configured");
        return A_TLS_ERR;
    }

    /*select own version and set it to tls->version*/
    tls->handshake_version = version;

    tls->version = version;

    if (version == A_TLS_GM_VERSION) {
        tls->flag = A_TLS_GM;

    } else if (version == A_TLS_TLS_1_0_VERSION) {
        tls->flag = A_TLS_1_0;

    } else if (version == A_TLS_TLS_1_1_VERSION) {
        tls->flag = A_TLS_1_1;

    } else if (version == A_TLS_TLS_1_2_VERSION) {
        tls->flag = A_TLS_1_2;

    } else {
        a_tls_error(tls, "tls recv version err:%d", version);
        return A_TLS_ERR;
    }

    return A_TLS_OK;
}

void a_tls_set_fd(a_tls_t *tls, s32 fd)
{
    tls->fd = fd;
}

void a_tls_cfg_free(a_tls_cfg_t *cfg)
{
    s32 i, j;

    for (i = 0; i < A_CRYPTO_NID_MAX; i++) {
        if (cfg->cert[i]) {
            X509_free(cfg->cert[i]);
        }

        if (cfg->pkey[i]) {
            EVP_PKEY_free(cfg->pkey[i]);
        }

        if (cfg->chain[i]) {
            a_tls_free(cfg->chain[i]);
        }

        for (j = 0; j < 10; j++) {
            if (cfg->der[i][j]) {
                a_tls_free(cfg->der[i][j]);
            }
        }

    }

    if (cfg->sign_cert) {
        X509_free(cfg->sign_cert);
    }

    if (cfg->sign_key) {
        EVP_PKEY_free(cfg->sign_key);
    }

    if (cfg->sign_der) {
        a_tls_free(cfg->sign_der);
    }

    a_tls_free(cfg);
}

void *a_tls_cfg_new()
{
    a_tls_cfg_t *ret;

    ret = a_tls_malloc(sizeof(a_tls_cfg_t));
    if (ret == NULL) {
        return NULL;
    }

    memset(ret, 0, sizeof(a_tls_cfg_t));

    ret->max_early_data = 16384;
    ret->cipers         = a_crypto_get_cipher_by_index(0);
    ret->srv_prefer     = 1;
    ret->ticket         = 1;
    return ret;
}

void a_tls_cfg_check_cert(a_tls_cfg_t *cfg)
{
    if (cfg->gm_support) {
        return;
    }

    if (cfg->sign_cert && cfg->sign_key
        && cfg->cert[A_CRYPTO_NID_SM] && cfg->pkey[A_CRYPTO_NID_SM]) {

        if (X509_check_private_key(cfg->sign_cert, cfg->sign_key)) {
            cfg->gm_support = 1;
        }
    }
}

void *a_tls_new(a_tls_cfg_t *cfg)
{
    a_tls_t * ret;

    ret = a_tls_malloc(sizeof(a_tls_t));
    if (ret == NULL) {
        return NULL;
    }

    memset(ret, 0, sizeof(a_tls_t));

    ret->state      = A_TLS_STATE_INIT;
    ret->cfg        = cfg;
    ret->state_proc = tls_state_proc;
    ret->spec       = &tls_spec;
    ret->support_gp = a_crypto_get_group_by_tls_id(A_CRYPTO_GROUP_ID_SECP256R1);

    a_tls_cfg_check_cert(cfg);

    return ret;
}

void a_tls_free_sess(a_tls_sess_t *sess)
{
    /*no session-id based resume, so session has no ref.*/
    if (sess->sni) {
        a_tls_free(sess->sni);
    }

    a_tls_free(sess);
}

void a_tls_free_tls(a_tls_t *tls)
{
    a_tls_err_t *tmp;
    u32 i;

    if (tls->buf) {
        a_tls_free(tls->buf);
    }

    if (tls->handshake) {
        a_tls_free_hs(tls->handshake);
    }

    if (tls->sess) {
        a_tls_free_sess(tls->sess);
    }

    if (tls->nbio) {
        a_tls_buf_free(tls->nbio);
    }

    if (tls->saved_app) {
        a_tls_buf_free(tls->saved_app);
    }

    if (tls->early_data) {
        a_tls_buf_free(tls->early_data);
    }

    if (tls->write_ctx) {
        EVP_CIPHER_CTX_free(tls->write_ctx);
    }

    if (tls->read_ctx) {
        EVP_CIPHER_CTX_free(tls->read_ctx);
    }

    while (tls->err_stack) {
        tmp = tls->err_stack;
        tls->err_stack = tls->err_stack->next;
        a_tls_free(tmp);
    }

    if (tls->last_err) {
        a_tls_free(tls->last_err);
    }

    a_tls_free(tls);
    i = 0;

    for (i = 0; i < sizeof(am_cnt)/sizeof(u32); i++) {
        if (am_cnt[i]){
            printf("size:%d cnt:%d\n", i , am_cnt[i]);
        }
    }
}

/*cfg*/
s32 a_tls_gen_tls_cert(a_tls_cfg_t *cfg, X509 **certs, u32 cert_index, s32 num, s32 pos)
{
    s32 idx = 0, i = 0, len;
    u8 *buf, *p ,*tmp;
    EVP_PKEY *certpk;
    X509 *x = NULL;
    X509 *sorted[10] = {NULL};

    x = certs[pos];
    sorted[idx++] = x;

    for(;;) {

        for(i = 0; i < num; i++) {
            if (i == pos) {
                continue;
            }

            if (X509_V_OK == X509_check_issued(certs[i], x)) {
                sorted[idx++] = certs[i];
                x = certs[i];
                break;
            }
        }

        /*x has no issuer in certs*/
        if (i == num) {
            break;
        }
    }

    certpk = X509_get_pubkey(sorted[0]);
    EVP_PKEY_free(certpk);

    /*Pre construct the certificate FOR TLS1.2*/
    len = 0;
    for(i = 0; i < idx; i++) {
        len += i2d_X509(sorted[i], NULL);
    }

    if ((buf = a_tls_malloc(len + i * 3)) == NULL) {
        return 0;
    }

    p = buf;
    for(i = 0; i < idx; i++)
    {
        tmp = p;
        p += 3;
        len = i2d_X509(sorted[i], &p);
        l2n3(len, tmp);
    }

    cfg->cert[cert_index]       = certs[pos];
    cfg->chain[cert_index]      = buf;
    cfg->chain_len[cert_index]  = (u32)(p - buf);

    /*FOR TLS1.3, we have to add extension for each certificate in chain*/

    for(i = 0; i < idx; i++) {

        len = i2d_X509(sorted[i], NULL);
        p = cfg->der[cert_index][i] = a_tls_malloc(len);
        if (p == NULL) {
            return 0;
        }

        cfg->der_len[cert_index][i] = len;

        if (len != i2d_X509(sorted[i], &p)) {
            printf("i2d_X509 err\n");
            return 0;
        }
    }
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    X509_up_ref(certs[pos]);
#else
    CRYPTO_add(&certs[pos]->references, 1, CRYPTO_LOCK_X509);
#endif

    return 1;
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
s32 a_tls_cfg_set_sign_key(a_tls_cfg_t *cfg, s8 *path)
{
    const EC_GROUP *grp = NULL;
    u32 type;
	BIO *in;
	EVP_PKEY *pkey;

    in = BIO_new_file((s8*)path, "r");
    if (in == NULL) {
        return 0;
    }

    pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    if (pkey == NULL) {
        return 0;
    }

    type = EVP_PKEY_id(pkey);

    if (type != EVP_PKEY_EC) {
        return 0;
    }

    grp = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey));

    if (EC_GROUP_get_curve_name(grp) != NID_sm2) {
        return 0;
    }

    cfg->sign_key = pkey;

    return 1;
}

s32 a_tls_cfg_set_sign_cert(a_tls_cfg_t *cfg, s8 *path)
{
    const EC_GROUP  *grp;
    BIO             *in;
    EVP_PKEY        *certpk;
    X509            *cert;
    u8              *p;
    u32 type, len;

    in = BIO_new_file((s8*)path, "r");
    if (in == NULL) {
        return 0;
    }

    cert = PEM_read_bio_X509(in, NULL, NULL, NULL);
    if (cert == NULL) {
        return 0;
    }

    certpk = X509_get_pubkey(cert);
    type = EVP_PKEY_id(certpk);
    EVP_PKEY_free(certpk);

    if (type != EVP_PKEY_EC) {
        return 0;
    }

    grp = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(certpk));

    if (EC_GROUP_get_curve_name(grp) != NID_sm2) {
        return 0;
    }

    cfg->sign_cert = cert;

    len = i2d_X509(cert, NULL);

    cfg->sign_der = a_tls_malloc(len);
    if (cfg->sign_der == NULL) {
        return 0;
    }

    p = cfg->sign_der;
    len = i2d_X509(cert, &p);

    cfg->sign_der_len = len;
    return 1;
}
#else
s32 a_tls_cfg_set_sign_cert(a_tls_cfg_t *cfg, s8 *path)
{
    printf("GM SSL need libcrypto.1.1\n");
    return 0;
}
s32 a_tls_cfg_set_sign_key(a_tls_cfg_t *cfg, s8 *path)
{
    printf("GM SSL need libcrypto.1.1\n");
    return 0;
}
#endif

s32 a_tls_cfg_set_cert(a_tls_cfg_t *cfg, s8 *path)
{
    BIO *in;
    EVP_PKEY *certpk;
    X509 *certs[10] = {NULL};
    s32 idx = 0, type, i, ret = 0, lowest = -1;
    u32 cert_index = 0, tmp_index = 0;

    in = BIO_new_file((s8*)path, "r");
    if (in == NULL) {
        return 0;
    }

    for (;;) {
        certs[idx] = PEM_read_bio_X509(in, NULL, NULL, NULL);
        if (certs[idx] == NULL) {
            ret = ERR_peek_last_error();
            if (ERR_GET_LIB(ret) == ERR_LIB_PEM
                && ERR_GET_REASON(ret) == PEM_R_NO_START_LINE)
            {
                /* end of file */
                ERR_clear_error();
                break;
            }
            BIO_free(in);
            return 0;
        }

        certpk = X509_get_pubkey(certs[idx]);
        type = EVP_PKEY_id(certpk);
        EVP_PKEY_free(certpk);

        if((type == EVP_PKEY_RSA) && cfg->pkey[A_CRYPTO_NID_RSA]) {
            tmp_index = A_CRYPTO_NID_RSA;
            ret = X509_check_private_key(certs[idx], cfg->pkey[A_CRYPTO_NID_RSA]);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        } else if ((type == EVP_PKEY_RSA_PSS) && cfg->pkey[A_CRYPTO_NID_RSAPSS]) {
            tmp_index = A_CRYPTO_NID_RSAPSS;
            ret = X509_check_private_key(certs[idx], cfg->pkey[A_CRYPTO_NID_RSAPSS]);
#endif
        } else if(type == EVP_PKEY_EC) {

            ret = 0;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
            const EC_GROUP *grp = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(certpk));
            if (EC_GROUP_get_curve_name(grp) == NID_sm2
                && cfg->pkey[A_CRYPTO_NID_SM])
            {
                tmp_index = A_CRYPTO_NID_SM;
                ret = X509_check_private_key(certs[idx], cfg->pkey[A_CRYPTO_NID_SM]);

            } else
#endif
            if (cfg->pkey[A_CRYPTO_NID_EC]) {
                tmp_index = A_CRYPTO_NID_EC;
                ret = X509_check_private_key(certs[idx], cfg->pkey[A_CRYPTO_NID_EC]);
            }

        } else {
            ret = 0;
        }

        if (ret) {
            /*we find the lowest certificate by the private key*/
            lowest = idx;
            cert_index  = tmp_index;
        }

        idx++;

        if ((u32)idx > sizeof(certs)/sizeof(void*)) {
            return 0;
        }
    }

    if (lowest == -1) {
        printf("certificate & key not match\n");
        return 0;
    }

    if (cfg->cert[cert_index]) {
        printf("same type certificate\n");
        return 0;
    }

//    a_tls_cfg_check_cert(cfg);

    ret = a_tls_gen_tls_cert(cfg, certs, cert_index, idx, lowest);

    for (i = 0; i < idx; i++) {
        X509_free(certs[i]);
    }

    return ret;
}

s32 a_tls_cfg_set_key(a_tls_cfg_t *cfg, s8 *path)
{
    const EC_GROUP *grp = NULL;
    u32 type;
	BIO *in;
	EVP_PKEY *pkey;

    in = BIO_new_file((s8*)path, "r");
    if (in == NULL) {
        return 0;
    }

    pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    if (pkey == NULL) {
        return 0;
    }

    type = EVP_PKEY_id(pkey);

    if (type == EVP_PKEY_RSA) {
        if (cfg->pkey[A_CRYPTO_NID_RSA] != NULL) {
            return 0;
        }
        cfg->pkey[A_CRYPTO_NID_RSA] = pkey;

    } else if (type == EVP_PKEY_EC) {

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        grp = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey));
#else
        grp = EC_KEY_get0_group(pkey->pkey.ec);
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        if (EC_GROUP_get_curve_name(grp) == NID_sm2) {
            if (cfg->pkey[A_CRYPTO_NID_SM] != NULL) {
                return 0;
            }

            cfg->pkey[A_CRYPTO_NID_SM] = pkey;
            return 1;

        } else
#endif
        if (cfg->pkey[A_CRYPTO_NID_EC] != NULL) {
            return 0;
        }

        cfg->pkey[A_CRYPTO_NID_EC] = pkey;
        cfg->curve = EC_GROUP_get_curve_name(grp);

    } else {
        return 0;
    }

    return 1;
}

void a_tls_init_env()
{
#if OPENSSL_VERSION_NUMBER >= 0x10100003L

            if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG
#ifndef OPENSSL_NO_AUTOLOAD_CONFIG
                                     | OPENSSL_INIT_LOAD_CONFIG
#endif
                                     | OPENSSL_INIT_ADD_ALL_CIPHERS
                                     | OPENSSL_INIT_ADD_ALL_DIGESTS,
                                     NULL))

        ERR_clear_error();

#else

        OPENSSL_config(NULL);
        OpenSSL_add_all_algorithms();

#endif
    a_tls_init_crypto_env();

}

s32 a_tls_get_handshake(a_tls_t *tls, s8 **data, u32 *len)
{
    if (tls->handshake == NULL) {
        return 0;
    }

    a_tls_get_hs_data(tls, (u8 **)data, len);
    return 1;
}

s32 a_tls_get_sni(a_tls_t *tls, s8 **data, u32 *len)
{
    if (tls->sess
        && tls->sess->sni
        && tls->sess->sni_len) {

        *data = (s8*)tls->sess->sni;
        *len  = tls->sess->sni_len;
        return 1;

    }

    if (tls->handshake
        && tls->handshake->sni
        && tls->handshake->sni_len) {

        *data = (s8*)tls->handshake->sni;
        *len  = tls->handshake->sni_len;
        return 1;
    }

    return 0;
}

s32 a_tls_get_protocol_name(a_tls_t *tls, s8 **data, u32 *len)
{
    *len = 7;

    if (tls->version == A_TLS_TLS_1_0_VERSION) {
        *data = "TLSv1.0";

    } else if (tls->version == A_TLS_TLS_1_1_VERSION) {
        *data = "TLSv1.1";

    } else if (tls->version == A_TLS_TLS_1_2_VERSION) {
        *data = "TLSv1.2";

    } else if (tls->version == A_TLS_TLS_1_3_VERSION) {
        *data = "TLSv1.3";

    } else if (tls->version == A_TLS_GM_VERSION) {
        *len = 10;
        *data = "GM SSL 1.1";

    } else {

        return 0;
    }

    return 1;
}

s32 a_tls_get_cipher_name(a_tls_t *tls, s8 **data, u32 *len)
{
    if (!tls->sess) {
        return 0;
    }

    *data = tls->sess->cipher->name;
    *len  = (u32)strlen(tls->sess->cipher->name);
    return 1;
}

s32 a_tls_get_sign_curve_name(a_tls_t *tls, s8 **data, u32 *len)
{
    sigalg_pair_t *sig;
    void          *key = NULL;
    a_md_t        *md = NULL;

    *len = 0;

    if (!tls->sess) {
        return 0;
    }

    if (!(tls->sess->cipher->flag&A_CRYPTO_CIPHER_ECDHE)
        && !(tls->sess->cipher->flag&A_CRYPTO_CIPHER_ECC)) {
        return 0;
    }

    sig = a_tls_select_sigalg(tls, &key, &md);

    *data = sig->name;
    *len  = (u32)strlen(sig->name);
    return 1;
}

s32 a_tls_get_exchange_curve_name(a_tls_t *tls, s8 **data, u32 *len)
{
    *len = 0;

    if (!tls->sess) {
        return 0;
    }

    if (!(tls->sess->cipher->flag&A_CRYPTO_CIPHER_ECDHE)
        && !(tls->sess->cipher->flag&A_CRYPTO_CIPHER_ECC)) {
        return 0;
    }

    if (IS_TLS13(tls)) {
        *data = tls->group->name;

    } else if (IS_TLSGM(tls)) {
        *data = "SM2";

    } else {
        *data = tls->support_gp->name;
    }

    *len = (u32)strlen(*data);
    return 1;
}

s32 a_tls_pop_err(a_tls_t *tls, s8 **data)
{
    if (tls->last_err) {
        a_tls_free(tls->last_err);
        tls->last_err = NULL;
    }

    if (tls->err_stack) {
        tls->last_err = tls->err_stack;
        tls->err_stack = tls->err_stack->next;
        *data = tls->last_err->str;
        return tls->last_err->str_len;
    }

    return 0;
}
