#include "a_crypto.h"
#include "a_tls.h"


/*TLS 1.3 */
s32 a_tls13_dec_gcm_openssl(void *arg, crypto_info_t *info)
{
    u8 iv[EVP_MAX_IV_LENGTH], header[5], *buf, *tmpbuf;
    s32 i, tmplen, len;
    a_cipher_t *cipher;
    u8 *c;
    u32 c_len;
    a_tls_t *tls = arg;

    c = info->c;
    c_len = info->c_len;

    cipher = tls->sess->cipher;

    /*first 4 bytes are the static_iv we derived from handshake*/
    memcpy(iv, tls->iv[0], cipher->iv_len - 8);

    /*last 8 bytes are the  counter[0..8]^static_iv[4..12] */
    for (i = 0; i < 8; i++) {
        iv[4 + i] = tls->iv[0][4 + i] ^ tls->seq[0][i];
    }

    /*update self seq*/
    for (i = 8; i > 0; i--) {
        ++tls->seq[0][i - 1];
        if (tls->seq[0][i - 1] != 0)
            break;
    }

    buf = header;

    *buf++ = A_TLS_RT_APPLICATION_DATA;
    s2n(tls->handshake_version, buf);
    s2n(c_len, buf);
#ifdef TLS_DEBUG
    {
       u32 i;
       printf("TLS13 GCM dec header %d\n",5);
       for(i=0;i<5;i++)
       {
           printf("%02X", header[i]);
       }
       printf("\n");
    }
    {
       u32 i;
       printf("TLS13 GCM dec iv %d\n",12);
       for(i=0;i<12;i++)
       {
           printf("%02X", iv[i]);
       }
       printf("\n");
    }
#endif
    tmpbuf = buf = a_tls_tmp_ciphertext_buf + 5;

    if (!EVP_CipherInit_ex(tls->read_ctx, NULL, NULL, NULL, iv, 0)
        || !EVP_CIPHER_CTX_ctrl(tls->read_ctx,
                                EVP_CTRL_GCM_SET_TAG,
                                EVP_GCM_TLS_TAG_LEN,
                                c + c_len - EVP_GCM_TLS_TAG_LEN)
        || !EVP_CipherUpdate(tls->read_ctx, NULL, &tmplen, header, sizeof(header))
        || !EVP_CipherUpdate(tls->read_ctx, tmpbuf, &len, c, c_len - EVP_GCM_TLS_TAG_LEN)
        || !EVP_CipherFinal_ex(tls->read_ctx, tmpbuf, &tmplen))
    {
        printf("dec err\n");
        return A_TLS_ERR;
    }
#ifdef TLS_DEBUG
    {
       s32 i;
       printf("TLS13 GCM dec len %d\n",len);
       for(i=0;i<len;i++)
       {
           printf("%02X", buf[i]);
       }
       printf("\n");
    }
#endif
    for(i = len - 1; i > 0 && buf[i] == 0; i--) {
        continue;
    }

    if (buf[i] != A_TLS_RT_HANDHSHAKE
        && buf[i] != A_TLS_RT_APPLICATION_DATA
        && buf[i] != A_TLS_RT_ALERT)
    {
        return A_TLS_ERR;
    }

    info->type = buf[i];

    memcpy(info->p, buf, i);
    info->p_len = i;

    return A_TLS_OK;
}

/*Enc buf p to buf c and set c's len to c_len*/
s32 a_tls13_enc_gcm_openssl(void *arg, crypto_info_t *info)
{
    /*tls1.3's add is type + zeros[zeronum]*/
    u8 iv[EVP_MAX_IV_LENGTH], header[5], *buf, type = info->type;
    s32 i, tmplen;
    a_cipher_t *cipher;
    u8 *p , *start;
    u32 p_len;
    a_tls_t *tls = arg;

    p = info->p;
    p_len = info->p_len;

    cipher = tls->sess->cipher;

    /*first 4 bytes are the static_iv we derived from handshake*/
    memcpy(iv, tls->iv[1], cipher->iv_len - 8);
#ifdef TLS_DEBUG
    {
        int k;
        printf("TLS13 GCM enc iv \n");
        for(k=0;k<12;k++)
        {
            printf("%02X",tls->iv[1][k]);
        }
        printf("\n");

        printf("TLS13 GCM enc seq \n");
        for(k=0;k<8;k++)
        {
            printf("%02X",tls->seq[1][k]);
        }
        printf("\n");
    }
#endif
    /*last 8 bytes are the  counter[0..8]^static_iv[4..12] */
    for (i = 0; i < 8; i++) {
        iv[4 + i] = tls->iv[1][4 + i] ^ tls->seq[1][i];
    }

    /*update self seq*/
    for (i = 8; i > 0; i--) {
        ++tls->seq[1][i - 1];
        if (tls->seq[1][i - 1] != 0)
            break;
    }

    buf = header;

    *buf++ = A_TLS_RT_APPLICATION_DATA;
    s2n(tls->handshake_version, buf);
    s2n((p_len + 1 + EVP_GCM_TLS_TAG_LEN), buf);

#ifdef TLS_DEBUG
    {
           u32 i;
           printf("TLS13 GCM enc header %d\n",5);
           for(i=0;i<5;i++)
           {
               printf("%02X", header[i]);
           }
           printf("\n");
    }
    {
           u32 i;
           printf("TLS13 GCM enc enc iv %d\n",12);
           for(i=0;i<12;i++)
           {
               printf("%02X", iv[i]);
           }
           printf("\n");
    }
#endif
    start = buf = a_tls_tmp_ciphertext_buf + 5;
    EVP_CipherInit_ex(tls->write_ctx, NULL, NULL, NULL, iv, 1);

    /*ADD*/
    EVP_CipherUpdate(tls->write_ctx, NULL, &tmplen, header, sizeof(header));

    /*enc*/
    EVP_CipherUpdate(tls->write_ctx, buf, &tmplen, p, p_len);
    buf += tmplen;
    EVP_CipherUpdate(tls->write_ctx, buf, &tmplen, &type, 1);/*TLS1.3 add*/
    buf += tmplen;
    EVP_CipherFinal_ex(tls->write_ctx, buf, &tmplen);

    /*GET TAG*/
    EVP_CIPHER_CTX_ctrl(tls->write_ctx,
        EVP_CTRL_GCM_GET_TAG,
        EVP_GCM_TLS_TAG_LEN,
        start + p_len + 1);

    info->c     = start;
    info->c_len = p_len + 1 + EVP_GCM_TLS_TAG_LEN;
    return A_TLS_OK;
}

s32 a_tls13_init_cipher(a_tls_t *tls, u32 flag)
{
    const EVP_CIPHER *cipher = tls->sess->cipher->cipher;
    void *ctx;
    u8 *key = NULL;

    /*write*/
    if (flag&A_TLS_SECRET_WRITE) {
        if (tls->write_ctx) {
            //EVP_CIPHER_CTX_reset
            EVP_CIPHER_CTX_cleanup(tls->write_ctx);
        } else {
            tls->write_ctx = EVP_CIPHER_CTX_new();
        }
        ctx = tls->write_ctx;
        key = tls->key[1];

    } else {
        if (tls->read_ctx) {
            //EVP_CIPHER_CTX_reset
            EVP_CIPHER_CTX_cleanup(tls->read_ctx);
        } else {
            tls->read_ctx = EVP_CIPHER_CTX_new();
        }
        ctx = tls->read_ctx;
        key = tls->key[0];
    }

    if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, NULL, flag&A_TLS_SECRET_WRITE))
    {
        printf("a_tls_init_cipher err 1\n");
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, tls->sess->cipher->iv_len, NULL))
    {
        printf("a_tls_init_cipher err 2\n");
    }

    return A_TLS_OK;
}

/*TLS1 TLS1.1 TLS 1.2 GMSSL CBC*/
s32 a_tls_enc_cbc_openssl(void *arg, crypto_info_t *info)
{
    a_tls_t *tls = arg;
    a_cipher_t *cipher = tls->sess->cipher;
    a_md_t *md = tls->sess->md;
    u8 *p       = info->p;
    u32 p_len   = info->p_len, new_len, i, random_iv = 0;
    u8 *buf, *start;
    u8 add[13];
    s32 ret;

    memcpy(add, tls->seq[1], 8);
    add[8]  = info->type;
    add[9]  = tls->handshake_version>>8;
    add[10] = tls->handshake_version&0xff;
    add[11] = (p_len)>>8;
    add[12] = (p_len)&0xff;

    new_len = (p_len + md->hash_size + cipher->block_size) & (~(cipher->block_size - 1));

    start = buf = a_tls_tmp_ciphertext_buf + 5;

    if (tls->version >= A_TLS_TLS_1_1_VERSION
        || tls->version == A_TLS_GM_VERSION)
    {
        random_iv = cipher->iv_len;
    }

    /*TODO*/
    buf += random_iv;
    memcpy(buf, p, p_len);
    buf += p_len;
    a_tls_gen_tls_hmac(md, tls->mac_key[1], add, sizeof(add), start + random_iv, p_len, buf);
    buf += md->hash_size;
    memset(buf, new_len - p_len - md->hash_size - 1, new_len - p_len - md->hash_size);
#ifdef TLS_DEBUG
    {
        int k;
        printf("CBC to be enc:%d\n",new_len + random_iv);
        for(k=0;(u32)k<new_len + random_iv;k++) {
            printf("%x ",start[k]);
        }
        printf("\n");
    }
#endif
    ret = EVP_Cipher(tls->write_ctx, start,
        start, new_len + random_iv);
    (void)ret;
#ifdef TLS_DEBUG
    printf("CBC EVP_Cipher ret:%d\n",ret);
#endif
    info->c = start;
    info->c_len = new_len + random_iv;

    /*update write seq*/
    for (i = 7; (s32)i >= 0; i--) {
        ++tls->seq[1][i];
        if(tls->seq[1][i] != 0) break;
    }
    return A_TLS_OK;
}

/*TLS 1 TLS1.1 TLS 1.2 CBC*/
s32 a_tls_dec_cbc_openssl(void *arg, crypto_info_t *info)
{
    a_tls_t *tls        = arg;
    a_md_t  *md         = tls->sess->md;
    a_cipher_t *cipher  = tls->sess->cipher;
    u8 *c                   = info->c, pad_val;
    u32 c_len               = info->c_len, pad_len, i, random_iv = 0;
    u8 add[13];
    u8 mac[A_CRYPTO_MAX_MD_LEN];

    if(EVP_Cipher(tls->read_ctx, c, c, c_len) <= 0) {
        printf("dec_cbc EVP_Cipher err\n");
        return A_TLS_ERR;
    }
#ifdef TLS_DEBUG
    {
        printf("CBC to be dec %d\n",c_len);
        for(i=0;i<c_len;i++)
            printf("%02X", c[i]);
        printf("\n");
    }
#endif
    pad_val = c[c_len - 1];
    pad_len = pad_val + 1;

    /*remove padding*/
    for (i = 0; i < pad_len; i++) {
        if (c[c_len - 1 - i] != pad_val) {
            printf("pad err\n");
            return A_TLS_ERR;
        }
    }

    if (tls->version >= A_TLS_TLS_1_1_VERSION
        || tls->version == A_TLS_GM_VERSION)
    {
        random_iv = cipher->iv_len;
    }

    info->p_len = c_len - random_iv - pad_len - md->hash_size;

    /*check MAC*/
    memcpy(add, tls->seq[0], 8);
    add[8] = info->type;
    add[9] = tls->handshake_version>>8;
    add[10]= tls->handshake_version&0xff;
    add[11] = (info->p_len)>>8;
    add[12] = (info->p_len)&0xff;
#ifdef TLS_DEBUG
    {
        printf("CBC dec add\n");
        for(i=0;i<13;i++)
            printf("%02X", add[i]);
        printf("\n");
    }
#endif
    a_tls_gen_tls_hmac(md, tls->mac_key[0], add, sizeof(add), c + random_iv, info->p_len, mac);

#ifdef TLS_DEBUG
    {
        printf("CBC dec hmac\n");
        for(i=0;i<md->hash_size;i++)
            printf("%02X", mac[i]);
        printf("\n");
    }
#endif

    if(memcmp(mac, c + c_len - pad_len - md->hash_size, md->hash_size))
    {
        printf("mac err\n");
        return A_TLS_ERR;
    }

    memcpy(info->p, c + random_iv, info->p_len);

    /*update read seq*/
    for (i = 7; (s32)i >= 0; i--) {
        ++tls->seq[0][i];
        if(tls->seq[0][i] != 0) break;
    }
    return A_TLS_OK;
}


/*TLS 1 TLS1.1 TLS 1.2 GCM*/
s32 a_tls_enc_gcm_openssl(void *arg, crypto_info_t *info)
{
    a_tls_t *tls = arg;
    u8 *p       = info->p;
    u32 p_len   = info->p_len, i;
    u8 *buf, *start;
    u8 add[13];
    s32 ret;

    memcpy(add, tls->seq[1], 8);
    add[8] = info->type;
    add[9] = tls->handshake_version>>8;
    add[10]= tls->handshake_version&0xff;
    add[11] = (p_len+8)>>8;
    add[12] = (p_len+8)&0xff;
#ifdef TLS_DEBUG
    {
        u32 k;
        printf("GCM enc add:\n");
        for(k=0;k<13;k++)
            printf("%02X", add[k]);
        printf("\n");
    }
#endif
    /*Set ADD for GCM*/
    if (EVP_CIPHER_CTX_ctrl(tls->write_ctx, EVP_CTRL_AEAD_TLS1_AAD, sizeof(add), add) <= 0)
        return A_TLS_ERR;

    start = buf = a_tls_tmp_ciphertext_buf + 5;
    buf += 8;
    memcpy(buf ,p, p_len);
    buf += p_len;

    ret = EVP_Cipher(tls->write_ctx, start,
        start, p_len + 8 + EVP_GCM_TLS_TAG_LEN);
    if (ret <=0 ) {
        printf("ENC err\n");
        return A_TLS_ERR;
    }
    info->c = start;
    info->c_len = p_len + 8 + EVP_GCM_TLS_TAG_LEN;

    /*update write seq*/
    for (i = 7; (s32)i >= 0; i--) {
        ++tls->seq[1][i];
        if(tls->seq[1][i] != 0) break;
    }
    return A_TLS_OK;
}

/*TLS 1 TLS1.1 TLS 1.2 GCM*/
s32 a_tls_dec_gcm_openssl(void *arg, crypto_info_t *info)
{
    a_tls_t *tls = arg;
    a_cipher_t *cipher = tls->sess->cipher;
    u8 *c       = info->c;
    u32 c_len   = info->c_len;
    u8 add[13];
    s32 i, ret;

    memcpy(add, tls->seq[0], 8);
    add[8] = info->type;
    add[9] = tls->handshake_version>>8;
    add[10]= tls->handshake_version&0xff;

    if (cipher->flag & A_CRYPTO_CIPHER_GCM) {
        add[11] = c_len>>8;
        add[12] = c_len&0xff;
#ifdef TLS_DEBUG
        {
            u32 k;
            printf("GCM dec add:\n");
            for(k=0;k<13;k++)
                printf("%02X", add[k]);
            printf("\n");
       }
#endif
        /*Set ADD for GCM*/
        EVP_CIPHER_CTX_ctrl(tls->read_ctx, EVP_CTRL_AEAD_TLS1_AAD, sizeof(add), add);
    }

    ret = EVP_Cipher(tls->read_ctx, c, c, c_len);
    if (ret <= 0) {
        printf("EVP_Cipher err\n");
        return A_TLS_ERR;
    }

    if (cipher->flag & A_CRYPTO_CIPHER_GCM) {
        memcpy(info->p, c + 8, ret);
        info->p_len = ret;
    } else {
        //todo remove padding
    }
    /*update read seq*/
    for (i = 7; i >= 0; i--) {
        ++tls->seq[0][i];
        if(tls->seq[0][i] != 0) break;
    }
    return A_TLS_OK;
}

s32 a_tls_cache_nbio_data(a_tls_t *tls, u8 *data, s32 data_len)
{
    if (tls->nbio == NULL) {
        tls->nbio = a_tls_buf_new(A_TLS_MAX_CACHE_BUF);
        if (tls->nbio == NULL) {
            a_tls_error(tls, "nbio new error");
            return A_TLS_ERR;
        }
    }

    if (tls->nbio->last + data_len > tls->nbio->end) {
        a_tls_error(tls, "nbio new len error :%p %p inlen:%d",
            tls->nbio->last, tls->nbio->end, data_len);
        return A_TLS_ERR;
    }

    tls->nbio->last = memcpy(tls->nbio->last, data, data_len);
    tls->nbio->last += data_len;
    return A_TLS_OK;
}

s32 a_tls_write(a_tls_t *tls, u8 *buf, u32 len)
{
    u8 *rc;
    s32 ret, remain, n, s, p;
    u32 input_len = len;
    crypto_info_t info;

    if (tls->state != A_TLS_STATE_ESTABLISH) {
        return A_TLS_WANT_WRITE;
    }

    /*remain data saved by last send*/
    if (tls->nbio) {
#ifdef TLS_DEBUG
        printf("send cache data first\n");
#endif
        p = tls->nbio->last - tls->nbio->pos;
        ret = a_tls_do_write(tls, tls->nbio->pos, p, &n);
        if (ret == A_TLS_WANT_WRITE
            || ret == A_TLS_ERR) {
            a_tls_error(tls, "a_tls_do_write nbio error:%d", ret);
            return ret;
        }

        tls->nbio->pos += n;
        if (tls->nbio->pos < tls->nbio->last) {
            return A_TLS_WANT_WRITE;
        }
        a_tls_buf_free(tls->nbio);
        tls->nbio = NULL;

        buf += tls->nbio_plain;
        len -= tls->nbio_plain;
    }

    p = 0;

#ifdef TLS_DEBUG
    printf("write data:%d\n", len);
#endif

    while(len) {

        s = (len > 16000)?16000:len;

        info.p = buf;
        info.p_len = s;
        info.type = A_TLS_RT_APPLICATION_DATA;
        tls->sess->cipher->enc(tls, &info);
        rc = info.c - A_TLS_HEAD_LEN;

        len -= s;
        buf += s;
        p += s;/*how many plantext we have crypted*/

        *rc++ = A_TLS_RT_APPLICATION_DATA;
        s2n(tls->handshake_version, rc);
        s2n(info.c_len, rc);

        ret = a_tls_do_write(tls, info.c - A_TLS_HEAD_LEN, info.c_len + A_TLS_HEAD_LEN, &n);
        if (ret == A_TLS_ERR) {
            a_tls_error(tls, "a_tls_do_write error:%d", ret);
            return A_TLS_ERR;
        }

        remain = info.c_len + A_TLS_HEAD_LEN - n;
        if (ret == A_TLS_OK) {
            if (remain == 0) {
                continue;
            }
        }

#ifdef TLS_DEBUG
        printf("cache data:%d\n", remain);
#endif
        ret = a_tls_cache_nbio_data(tls, info.c - A_TLS_HEAD_LEN + n, remain);
        if (ret != A_TLS_OK) {
            return ret;
        }
        tls->nbio_plain = p;
        return A_TLS_WANT_WRITE;
    }

    /*must equal to input length*/
    return input_len;
}

s32 a_tls_read(a_tls_t *tls, u8 *buf, u32 len)
{
    u8  *pos;
    s32 ret;
    u32 remain;
    msg_t msg;

    if (tls->state != A_TLS_STATE_ESTABLISH) {
        return A_TLS_WANT_READ;
    }

    if (tls->err) {
        return tls->err;
    }

    pos = buf;

    if (tls->early_data) {
        remain = tls->early_data->last - tls->early_data->pos;
        if (remain >= len) {
            memcpy(pos, tls->early_data->pos, len);
            tls->early_data->pos += len;
            return (s32)len;
        }

        memcpy(pos, tls->early_data->pos, remain);
        len -= remain;
        pos += remain;
        a_tls_buf_free(tls->early_data);
        tls->early_data = NULL;
    }

    if (tls->saved_app) {
        remain = tls->saved_app->last - tls->saved_app->pos;
        if (remain >= len) {
            memcpy(pos, tls->saved_app->pos, len);
            tls->saved_app->pos += len;
            return (s32)len;

        } else {
            memcpy(pos, tls->saved_app->pos, remain);
            pos += remain;
            len -= remain;
            a_tls_free(tls->saved_app);
            tls->saved_app = NULL;
        }
    }

again:
    msg.len = 0;
    ret = a_tls_get_message(tls, &msg, A_TLS_RT_APPLICATION_DATA);
    if (ret != A_TLS_OK) {
        if (pos > buf) {

            if (ret != A_TLS_WANT_READ) {
                tls->err = ret;
            }

            return (s32)(pos - buf);
        }

        return ret;
    }

    if (msg.len <= len) {
        memcpy(pos, msg.data, msg.len);
        pos += msg.len;
        len -= msg.len;
        if (!len) {
            return (s32)(pos - buf);
        }
        goto again;

    } else {
        remain = msg.len - len;
        if (tls->saved_app == NULL) {
            tls->saved_app = a_tls_buf_new(remain);
            if (tls->saved_app == NULL) {
                a_tls_error(tls, "new save app");
                return A_TLS_ERR;
            }
        }

        memcpy(pos, msg.data, len);
        pos += len;

        memcpy(tls->saved_app->last, msg.data + len, remain);
        tls->saved_app->last += remain;
        return (s32)(pos - buf);
    }
}

s32 a_tls_init_cipher(a_tls_t *tls, u32 flag)
{
    void *ctx, *cipher_key, *cipher_iv, *mac_key;
    a_cipher_t *cipher;
    a_md_t *md;
    u32 iv_len, key_len, md_len;
    const EVP_CIPHER *cipher2;
    u8 *key;

    md = tls->sess->md;
    cipher = tls->sess->cipher;

    iv_len  = cipher->iv_len;
    key_len = cipher->key_len;
    md_len  = md->hash_size;
    cipher2 = cipher->cipher;

    if (cipher->flag & A_CRYPTO_CIPHER_GCM)  {
        /*fixed iv length*/
        iv_len = 4;
        md_len = 0;
    }

    if (flag&A_TLS_SECRET_WRITE) {
        if (tls->write_ctx) {
            //EVP_CIPHER_CTX_reset
            EVP_CIPHER_CTX_cleanup(tls->write_ctx);

        } else {
            tls->write_ctx = EVP_CIPHER_CTX_new();
        }
        ctx = tls->write_ctx;
        cipher_key = tls->key[1];
        cipher_iv = tls->iv[1];
        mac_key = tls->mac_key[1];

    } else {
        if (tls->read_ctx) {
            //EVP_CIPHER_CTX_reset
            EVP_CIPHER_CTX_cleanup(tls->read_ctx);

        } else {
            tls->read_ctx = EVP_CIPHER_CTX_new();
        }
        ctx = tls->read_ctx;
        cipher_key = tls->key[0];
        cipher_iv = tls->iv[0];
        mac_key = tls->mac_key[0];
    }

    key = tls->handshake->key_block;
    /*server write*/
    if (flag&A_TLS_SECRET_SRV
        && flag&A_TLS_SECRET_WRITE)
    {
        key += md_len;
        memcpy(mac_key, key, md_len);
        key += md_len;
        key += key_len;
        memcpy(cipher_key, key, key_len);
        key += key_len;
        key += iv_len;
        memcpy(cipher_iv, key, iv_len);
    }

    key = tls->handshake->key_block;
    if (flag&A_TLS_SECRET_SRV
        && flag&A_TLS_SECRET_READ)
    {
        memcpy(mac_key, key, md_len);
        key += md_len;
        key += md_len;
        memcpy(cipher_key, key, key_len);
        key += key_len;
        key += key_len;
        memcpy(cipher_iv, key, iv_len);
    }
#ifdef TLS_DEBUG
    {
        u32 k;
        printf("init cipher write:%d\n",!!(flag&A_TLS_SECRET_WRITE));
        printf("cipher_key:%d\n", key_len);
        for(k=0;k<key_len;k++)
        {
            printf("%02X",((u8*)cipher_key)[k]);
        }
        printf("\n");
        printf("cipher_iv:%d\n",iv_len);
        for(k=0;k<iv_len;k++)
        {
            printf("%02X",((u8*)cipher_iv)[k]);
        }
        printf("\n");

        printf("mac key:%d\n",md_len);
        for(k=0;k<md_len;k++)
        {
            printf("%02X",((u8*)mac_key)[k]);
        }
        printf("\n");
    }
#endif
    if (cipher->flag & A_CRYPTO_CIPHER_GCM) {
        if (!EVP_CipherInit_ex(ctx, cipher2, NULL, cipher_key, NULL, !!(flag&A_TLS_SECRET_WRITE))
            || !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, iv_len,
                                    cipher_iv)) {
                a_tls_error(tls, "tls init cipher err");
                return A_TLS_ERR;
        }

    } else {
        if(!EVP_CipherInit_ex(ctx, cipher2, NULL, cipher_key, cipher_iv, !!(flag&A_TLS_SECRET_WRITE)))
        {
            a_tls_error(tls, "tls init cipher err");
            return A_TLS_ERR;
        }
    }

    return A_TLS_OK;
}

