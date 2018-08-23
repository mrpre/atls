#include "a_crypto.h"
#include "a_tls.h"
s32 a_tls_snd_srv_hello(a_tls_t *tls);
s32 a_tls_snd_srv_cert(a_tls_t *tls);
s32 a_tls_snd_srv_ske(a_tls_t *tls);
s32 a_tls_snd_srv_done(a_tls_t *tls);
s32 a_tls_get_clnt_cke(a_tls_t *tls);
s32 a_tls_get_clnt_ccs(a_tls_t *tls);
s32 a_tls_get_clnt_finished(a_tls_t *tls);
s32 a_tls_snd_srv_ccs(a_tls_t *tls);
s32 a_tls_snd_srv_ticket(a_tls_t *tls);
s32 a_tls_snd_srv_finished(a_tls_t *tls);
s32 a_tls_change_cipher_spec(a_tls_t *tls, u32 flag);

s32 a_tls_enc(a_tls_t *tls, crypto_info_t *info)
{
    return tls->sess->cipher->enc(tls, info);
}

s32 a_tls_dec(a_tls_t *tls, crypto_info_t *info)
{
    return tls->sess->cipher->dec(tls, info);
}

method_t tls_spec =
{
    .enc            = a_tls_enc,
    .dec            = a_tls_dec,
    .change_cipher  = a_tls_change_cipher_spec,
    .init_cipher    = a_tls_init_cipher,
    .flag           = (A_CRYPTO_CIPHER_TLS1
                        |A_CRYPTO_CIPHER_TLS1_1
                        |A_CRYPTO_CIPHER_TLS1_2),
};

state_func tls_state_proc[A_TLS_STATE_MAX] =
{
    [A_TLS_STATE_INIT]              = a_tls_init,
    [A_TLS_STATE_GET_CLNT_HELLO]    = a_tls_get_clnt_hello,
    [A_TLS_STATE_SND_SRV_HELLO]     = a_tls_snd_srv_hello,
    [A_TLS_STATE_SND_SRV_CERT]      = a_tls_snd_srv_cert,
    [A_TLS_STATE_SND_SRV_KE]        = a_tls_snd_srv_ske,
    [A_TLS_STATE_SND_SRV_DONE]      = a_tls_snd_srv_done,
    [A_TLS_STATE_GET_CLNT_CKE]      = a_tls_get_clnt_cke,
    [A_TLS_STATE_GET_CLNT_CCS]      = a_tls_get_clnt_ccs,
    [A_TLS_STATE_GET_CLNT_FINISH]   = a_tls_get_clnt_finished,
    [A_TLS_STATE_SND_SRV_CCS]       = a_tls_snd_srv_ccs,
    [A_TLS_STATE_SND_SRV_TICKET]    = a_tls_snd_srv_ticket,
    [A_TLS_STATE_SND_SRV_FINISH]    = a_tls_snd_srv_finished,
};

s32 a_tls_change_cipher_spec(a_tls_t *tls, u32 flag)
{
    a_cipher_t *cipher;
    a_md_t *md;
    u32 iv_len, key_len, md_len, kb_size;
    u8 *p, buf[A_TLS_MAX_KB_LABEL_LEN];

    md = tls->sess->md;
    cipher = tls->sess->cipher;

    iv_len  = cipher->iv_len;
    key_len = cipher->key_len;
    md_len  = md->hash_size;

    if (cipher->flag & A_CRYPTO_CIPHER_GCM) {
        /*fixed iv length*/
        iv_len = 4;
    }

    /*generate key block*/
    if(tls->handshake->key_block == NULL) {
        kb_size = (iv_len + key_len + md_len)<<1;
        tls->handshake->key_block = a_tls_malloc(kb_size * 2);
        if (tls->handshake->key_block == NULL) {
            return A_TLS_ERR;
        }

        p = buf;
        memcpy(p, A_TLS_KEY_EXPANSION_CONST, A_TLS_KEY_EXPANSION_CONST_LEN);
        p +=  A_TLS_KEY_EXPANSION_CONST_LEN;

        memcpy(p, tls->handshake->srv_random, A_TLS_RAND_SIZE);
        p += A_TLS_RAND_SIZE;

        memcpy(p, tls->handshake->clnt_random, A_TLS_RAND_SIZE);

        a_tls_prf(tls, buf, sizeof(buf), tls->sess->master_secret, A_TLS_PRE_MASTER_KEY_LEN, tls->handshake->key_block, tls->handshake->key_block + kb_size, kb_size);
#ifdef TLS_DEBUG
        {
            u32 i;
            printf("kb_size:%d\n",kb_size);
            for(i=0;i<kb_size;i++)
            {
                printf("%02X", tls->handshake->key_block[i]);
            }
            printf("\n");
        }
#endif
    }

    a_tls_init_cipher(tls, flag);
    return A_TLS_OK;
}

s32 a_tls_process_cke(a_tls_t *tls, msg_t *msg)
{
    u8 *p   = msg->data;
    u32 len = msg->len, len2;

    if (*p++ != A_TLS_MT_CLNT_KEYEXCHANGE) {
        a_tls_error(tls, "cke type error:%d", *(p-1));
        return A_TLS_ERR;
    }

    n2l3(p, len2);

    if (len2 + 4 != len) {
        a_tls_error(tls, "cke len error len1:%d len2:%d", len, len2);
        return A_TLS_ERR;
    }

    /*Will generate master secret*/
    if (tls->sess->cipher->parse_cke((void*)tls, p, len2)
        != A_TLS_OK)
    {
        a_tls_error(tls, "parse_cke error");
        return A_TLS_ERR;
    }

    tls->state = A_TLS_STATE_GET_CLNT_CCS;
    return A_TLS_OK;
}

s32 a_tls_get_finished_prf(a_tls_t *tls, u32 self, u8 *out)
{
    u8 hash[A_CRYPTO_MAX_MD_LEN], check_buf[15 + A_CRYPTO_MAX_MD_LEN];
    u8 tmp1[A_CRYPTO_MAX_MD_LEN];
    u8 *hs;
    u32 hs_len, hash_size;

    /*check finished*/
    a_tls_get_hs_data(tls, &hs, &hs_len);
#ifdef TLS_DEBUG
    {
                int k;
                printf("finished handshake:%d\n",hs_len);
                for(k=0;(u32)k<hs_len;k++)
                    printf("%02x",hs[k]);
                printf("\n");
    }
#endif
    if (tls->version == A_TLS_TLS_1_2_VERSION) {

        if(A_CRYPTO_NID_SHA384 == tls->sess->md->nid) {
            a_md_do_digest(a_sha384, hs, hs_len, hash);
            hash_size = a_sha384->hash_size;

        } else {
            a_md_do_digest(a_sha256, hs, hs_len, hash);
            hash_size = a_sha256->hash_size;
        }

    } else if (IS_TLSGM(tls)) {
        a_md_do_digest(tls->sess->md, hs, hs_len, hash);
        hash_size = tls->sess->md->hash_size;

    } else {
        a_md_do_digest(a_md5, hs, hs_len, hash);
        a_md_do_digest(a_sha1, hs, hs_len, hash + 16);
        hash_size = a_md5->hash_size + a_sha1->hash_size;
    }

    if ((tls->dir && self)
        || (!tls->dir && !self))
    {
        memcpy(check_buf, A_TLS_MD_SERVER_FINISH_CONST, A_TLS_MD_SERVER_FINISH_CONST_SIZE);
        memcpy(check_buf + A_TLS_MD_SERVER_FINISH_CONST_SIZE, hash, hash_size);

    } else {
        memcpy(check_buf, A_TLS_MD_CLIENT_FINISH_CONST, A_TLS_MD_CLIENT_FINISH_CONST_SIZE);
        memcpy(check_buf + A_TLS_MD_CLIENT_FINISH_CONST_SIZE, hash, hash_size);
    }

    a_tls_prf(tls, check_buf, A_TLS_MD_CLIENT_FINISH_CONST_SIZE + hash_size,
        tls->sess->master_secret, A_TLS_MASTER_KEY_LEN, out, tmp1, 12);

    return A_TLS_OK;
}

s32 a_tls_snd_srv_ticket(a_tls_t *tls)
{
    u8 *p = a_tls_tmp_msg_buf, *l, *l2;
    u32 len;

    *p++ = A_TLS_MT_SESS_TICKET;

    l = p;
    p += 3;

    l2n(7200, p);
    l2 = p;
    p += 2;

    a_tls_gen_session_ticket(tls, p, &len);
    p += len;

    s2n(len, l2);
    len = (u32)(p - a_tls_tmp_msg_buf);
    l2n3(len - 4, l);

    tls->state = A_TLS_STATE_SND_SRV_CCS;

    return a_tls_snd_msg(tls, a_tls_tmp_msg_buf, (u32)(p - a_tls_tmp_msg_buf), A_TLS_RT_HANDHSHAKE);
}

s32 a_tls_snd_srv_finished(a_tls_t *tls)
{
    u8 *p = a_tls_tmp_msg_buf;

    *p++ = A_TLS_MT_FINISHED;
    l2n3(12, p);

    a_tls_get_finished_prf(tls, 1, p);

    p += 12;

    if (tls->hit) {
        tls->state = A_TLS_STATE_GET_CLNT_CCS;

    } else {
        tls->state = A_TLS_STATE_ESTABLISH;
    }

    return a_tls_snd_msg(tls, a_tls_tmp_msg_buf, (u32)(p - a_tls_tmp_msg_buf), A_TLS_RT_HANDHSHAKE);
}

s32 a_tls_snd_srv_ccs(a_tls_t *tls)
{
    u8 *p = a_tls_tmp_msg_buf;

    *p++ = 0x01;

    tls->state = A_TLS_STATE_SND_SRV_FINISH;

    a_tls_change_cipher(tls, A_TLS_SECRET_SRV|A_TLS_SECRET_WRITE);
    return a_tls_snd_msg(tls, a_tls_tmp_msg_buf, (u32)(p - a_tls_tmp_msg_buf), A_TLS_RT_CCS);
}

s32 a_tls_get_clnt_finished(a_tls_t *tls)
{
    msg_t msg;
    s32 ret;
    u32 len;
    u8 *p;
    u8 prf[12];

    ret = a_tls_get_message(tls, &msg, A_TLS_RT_HANDHSHAKE);
    if (ret != A_TLS_OK) {
        return ret;
    }

    p = msg.data;
#ifdef TLS_DEBUG
    {
            u32 i;
            printf("recv finished:%d\n",msg.len);
            for(i=0;i<msg.len;i++)
            {
                printf("%02X", msg.data[i]);
            }
            printf("\n");
     }
#endif
    if (*p++ != A_TLS_MT_FINISHED)
    {
        a_tls_error(tls, "clnt finished type error %d", *(p-1));
        return A_TLS_ERR;
    }

    n2l3(p, len);

    if (len != msg.len - 4
        || len != 12)
    {
        a_tls_error(tls, "clnt finished len error len:%d msg.len:%d", len, msg.len);
        return A_TLS_ERR;
    }

    a_tls_get_finished_prf(tls, 0 ,prf);

    if(memcmp(prf, p, 12)) {
        a_tls_error(tls, "clnt finished prf error");
        return A_TLS_ERR;
    }

    a_tls_save_hs(tls, msg.data, msg.len);

    if (tls->hit) {
        tls->state = A_TLS_STATE_ESTABLISH;

    } else {
        if (tls->cfg->ticket
            && tls->ext.sess_tikcet)
        {
            tls->state = A_TLS_STATE_SND_SRV_TICKET;

        } else {
            tls->state = A_TLS_STATE_SND_SRV_CCS;
        }
    }
    return A_TLS_OK;
}

s32 a_tls_get_clnt_ccs(a_tls_t *tls)
{
    msg_t msg;
    s32 ret;

    ret = a_tls_get_message(tls, &msg, A_TLS_RT_HANDHSHAKE);
    if (ret != A_TLS_OK) {
        a_tls_error(tls, "clnt ccs get message error:%d", ret);
        return ret;
    }

    if (msg.len != 1) {
        a_tls_error(tls, "clnt ccs len error:%d",msg.len);
        return A_TLS_ERR;
    }

    a_tls_change_cipher(tls, A_TLS_SECRET_SRV|A_TLS_SECRET_READ);
    tls->state = A_TLS_STATE_GET_CLNT_FINISH;
    return A_TLS_OK;
}

s32 a_tls_get_clnt_cke(a_tls_t *tls)
{
    msg_t msg;
    s32 ret;

    ret = a_tls_get_message(tls, &msg, A_TLS_RT_HANDHSHAKE);
    if (ret != A_TLS_OK) {
        a_tls_error(tls, "clnt ccs get message error:%d", ret);
        return ret;
    }

    a_tls_save_hs(tls, msg.data, msg.len);

    ret = a_tls_process_cke(tls, &msg);
    if (ret != A_TLS_OK) {
        a_tls_error(tls, "a_tls_process_cke error:%d", ret);
        return ret;
    }
    tls->state = A_TLS_STATE_GET_CLNT_CCS;
    return A_TLS_OK;
}

s32 a_tls_snd_srv_done(a_tls_t *tls)
{
    u8 *p = a_tls_tmp_msg_buf;

    *p++ = A_TLS_MT_SRV_DONE;
    l2n3(0, p);
    tls->state = A_TLS_STATE_GET_CLNT_CKE;
    return a_tls_snd_msg(tls, a_tls_tmp_msg_buf, 4, A_TLS_RT_HANDHSHAKE);
}

s32 a_tls_get_ske_tbs(a_tls_t *tls, u8 *in, u32 in_len, u8 *tbs, u32 *tbs_len)
{
    memcpy(tbs, tls->handshake->clnt_random, A_TLS_RAND_SIZE);
    memcpy(tbs + A_TLS_RAND_SIZE, tls->handshake->srv_random, A_TLS_RAND_SIZE);
    memcpy(tbs + A_TLS_RAND_SIZE + A_TLS_RAND_SIZE, in, in_len);

    *tbs_len = A_TLS_RAND_SIZE + A_TLS_RAND_SIZE + in_len;
    return A_TLS_OK;
}

s32 a_tls_snd_srv_ske_gm(a_tls_t *tls)
{
    sigalg_pair_t *sig;
    crypto_info_t info;
    a_md_t *md = NULL;
    void   *key = NULL;
    u8 *p = a_tls_tmp_msg_buf, *l;
    u8 *sign_start;
    u32 tbs_len, sign_len;
    u8 *tbs, *sig_tmp;

    *p++ = A_TLS_MT_SRV_KEYEXCHANGE;

    l = p;
    p += 3;

    sign_start = tls->cfg->der[A_CRYPTO_NID_SM][0];
    sign_len   = tls->cfg->der_len[A_CRYPTO_NID_SM][0];

    sig = a_tls_select_sigalg(tls, NULL, &md);

    tbs = a_tls_malloc(sign_len + A_TLS_RAND_SIZE*2 + 3);
    if (tbs == NULL) {
        a_tls_error(tls, "ske gm nomem");
        return A_TLS_ERR;
    }

    sig_tmp = tbs;

    memcpy(sig_tmp, tls->handshake->clnt_random, A_TLS_RAND_SIZE);
    sig_tmp += A_TLS_RAND_SIZE;
    memcpy(sig_tmp, tls->handshake->srv_random, A_TLS_RAND_SIZE);
    sig_tmp += A_TLS_RAND_SIZE;
    l2n3(sign_len, sig_tmp);
    memcpy(sig_tmp, sign_start, sign_len);
    sig_tmp += sign_len;

    tbs_len = (u32)(sig_tmp - tbs);

    /*use the sign key*/
    key = tls->cfg->sign_key;

    memset(&info.async, 0 ,sizeof(info.async));

    info.async.md = NULL;
    info.async.tbs = tbs;
    info.async.tbs_len = tbs_len;
    info.async.mode = sig->mode;
    info.async.key = key;
    info.async.out = p+2;
    info.async.out_len = &sign_len;

    if (sig->sign(NULL, &info) != A_TLS_OK) {
        a_tls_error(tls, "ske gm sign error");
        return A_TLS_ERR;
    }

    s2n(sign_len, p);
    p += sign_len;

    sign_len = (u32)(p - a_tls_tmp_msg_buf);
    l2n3((sign_len - 4), l);
    tls->state = A_TLS_STATE_SND_SRV_DONE;
    return a_tls_snd_msg(tls, a_tls_tmp_msg_buf, sign_len, A_TLS_RT_HANDHSHAKE);

}
s32 a_tls_snd_srv_ske(a_tls_t *tls)
{
    sigalg_pair_t *sig;
    crypto_info_t info;
    a_md_t *md = NULL;
    void *key = NULL;
    s32 sign_len;
    u32 tbs_len, len;
    u8 *p = a_tls_tmp_msg_buf, *l;
    u8 *sign_start, tbs[A_TLS_RAND_SIZE*2 + 5 + A_CRYPTO_MAX_EC_PUB_LEN];
    a_tls_handshake_t *hs = tls->handshake;

    if (!(tls->sess->cipher->flag&A_CRYPTO_CIPHER_ECDHE)
        && ! (tls->sess->cipher->flag&A_CRYPTO_CIPHER_ECC))
    {
        tls->state = A_TLS_STATE_SND_SRV_DONE;
        return A_TLS_OK;
    }

    if (IS_TLSGM(tls)) {
        return a_tls_snd_srv_ske_gm(tls);
    }

    *p++ = A_TLS_MT_SRV_KEYEXCHANGE;
    l = p;
    p += 3;

    sign_start = p;
    *p++ = 0x03;/*named curve*/
    s2n(tls->support_gp->tls_nid, p);

    a_crypto_gen_ec_pub(
                 tls->support_gp,
                 &hs->self_ecdh_prv, &hs->self_ecdh_pub,
                 &hs->self_ecdh_prv_len, &hs->self_ecdh_pub_len);

    *p++ = hs->self_ecdh_pub_len;
    memcpy(p, hs->self_ecdh_pub, hs->self_ecdh_pub_len);
    p += hs->self_ecdh_pub_len;

    sign_len = (u32)(p - sign_start);

    sig = a_tls_select_sigalg(tls, &key, &md);

    /*Use single hash function*/
    if (tls->version == A_TLS_TLS_1_2_VERSION) {
        s2n(sig->tls_id, p);
    }

    a_tls_get_ske_tbs(tls, sign_start, sign_len, tbs, &tbs_len);
#ifdef TLS_DEBUG
    {
        u32 k;
        printf("tbs :%d\n",tbs_len);
        for(k=0;k<tbs_len;k++)
            printf("%02X", tbs[k]);
        printf("\n");
    }
#endif
    memset(&info.async, 0 ,sizeof(info.async));

    info.async.md = md;
    info.async.tbs = tbs;
    info.async.tbs_len = tbs_len;
    info.async.mode = sig->mode;
    info.async.key = key;
    info.async.out = p+2;
    info.async.out_len = &len;

    if (sig->sign(NULL, &info) != A_TLS_OK) {
        a_tls_error(tls, "ske sign error");
        return A_TLS_ERR;
    }

    s2n(len, p);
    p += len;

    len = (u32)(p - a_tls_tmp_msg_buf);
    l2n3((len - 4), l);
    tls->state = A_TLS_STATE_SND_SRV_DONE;
    return a_tls_snd_msg(tls, a_tls_tmp_msg_buf, len, A_TLS_RT_HANDHSHAKE);
}

s32 a_tls_snd_srv_cert_gm(a_tls_t *tls)
{
    s32 len;
    u8 *p = a_tls_tmp_msg_buf, *l;

    *p++ = A_TLS_MT_CERT;
    l = p;
    p += 3;

    len = tls->cfg->sign_der_len + tls->cfg->der_len[A_CRYPTO_NID_SM][0];
    l2n3(len + 6, p);

    /*signed cert*/
    len = tls->cfg->sign_der_len;
    l2n3(len, p);
    memcpy(p, tls->cfg->sign_der, len);
    p += len;

    /*enc cert*/
    len = tls->cfg->der_len[A_CRYPTO_NID_SM][0];
    l2n3(len, p);
    memcpy(p, tls->cfg->der[A_CRYPTO_NID_SM][0], len);
    p += len;

    len = (u32)(p - a_tls_tmp_msg_buf);
    l2n3((len - 4), l);

    tls->state = A_TLS_STATE_SND_SRV_KE;
    return a_tls_snd_msg(tls, a_tls_tmp_msg_buf, len, A_TLS_RT_HANDHSHAKE);

}

s32 a_tls_snd_srv_cert(a_tls_t *tls)
{
    s32 len ,index = 0;
    u8 *p = a_tls_tmp_msg_buf, *l;

    if (IS_TLSGM(tls)) {
        return a_tls_snd_srv_cert_gm(tls);
    }

    *p++ = A_TLS_MT_CERT;
    l = p;
    p += 3;

    index = tls->selected_cert;

    len = tls->cfg->chain_len[index];
    l2n3(len, p);
    memcpy(p, tls->cfg->chain[index], len);
    p += len;

    len = (u32)(p - a_tls_tmp_msg_buf);
    l2n3((len - 4), l);

    tls->state = A_TLS_STATE_SND_SRV_KE;
    return a_tls_snd_msg(tls, a_tls_tmp_msg_buf, len, A_TLS_RT_HANDHSHAKE);

}

s32 a_tls_snd_srv_hello(a_tls_t *tls)
{
    s32 len;
    u8 *p = a_tls_tmp_msg_buf, *l;

    *p++ = A_TLS_MT_SRV_HELLO;
    l = p;
    p += 3;

    len = a_tls_construct_srv_hello(tls, p);
    if (len <= 0) {
        a_tls_error(tls, "srv hello new error");
        return A_TLS_ERR;
    }

    p += len;

    /*extension*/
    len = a_tls_construct_extension(tls, p + 2, A_TLS_MT_SRV_HELLO);
    if (len) {
        s2n(len, p);
        p += len;
    }

    len = (u32)(p - a_tls_tmp_msg_buf);
    l2n3((len - 4), l);

    if (tls->hit) {
        tls->state = A_TLS_STATE_SND_SRV_CCS;

    } else {
        tls->state = A_TLS_STATE_SND_SRV_CERT;
    }

    return a_tls_snd_msg(tls, a_tls_tmp_msg_buf, len, A_TLS_RT_HANDHSHAKE);
}

/*All protocol start here*/
s32 a_tls_get_clnt_hello(a_tls_t *tls)
{
    msg_t msg;
    s32 ret;

    ret = a_tls_get_message(tls, &msg, A_TLS_RT_HANDHSHAKE);
    if (ret != A_TLS_OK) {
        return ret;
    }

    ret = a_tls_save_hs(tls, msg.data, msg.len);
    if (ret != A_TLS_OK) {
        return ret;
    }

    ret = a_tls_process_clnt_hello(tls, &msg);
    if (ret != A_TLS_OK) {
        return ret;
    }

    tls->state = A_TLS_STATE_SND_SRV_HELLO;

    if (!IS_TLS13(tls)) {
        return A_TLS_OK;
    }

    if (tls->sig == NULL) {
        a_tls_error(tls, "clnt sig err");
        return A_TLS_ERR;
    }

    if (!tls->cfg->pkey[A_CRYPTO_NID_RSA]
        && !tls->cfg->pkey[A_CRYPTO_NID_EC]
        && !tls->cfg->pkey[A_CRYPTO_NID_RSAPSS]) {
        a_tls_error(tls, "TLS 1.3 with not appropriate certificate");
        return A_TLS_ERR;
    }

    /*the tls1.3's cipher doesn't contain sig info*/
    tls->selected_cert = tls->sig->pkey;

    /*In TLS 1.3 we may need to read early data*/
    if (tls->ext.early_data == A_TLS_EARLY_DATA_ACCEPTING) {
        //psk handshake
        if (tls->hit) {
            tls->ext.early_data = A_TLS_EARLY_DATA_ACCEPTED;
            /*The handshake buf now only contain 'ClientHello'*/
            ret = a_tls_change_cipher(tls, A_TLS_SECRET_READ|A_TLS_SECRET_EARLY);
            if (ret != A_TLS_OK) {
                return ret;
            }

        } else {
            /*The client send early data but we must drop it*/
            tls->ext.early_data = A_TLS_EARLY_DATA_REJECT;
        }
    }

    return A_TLS_OK;
}

