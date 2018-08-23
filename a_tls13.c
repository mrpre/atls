#include "a_crypto.h"
#include "a_tls.h"

s32 a_tls_get_clnt_hello(a_tls_t *tls);
s32 a_tls_get_clnt_cke(a_tls_t *tls);
s32 a_tls13_snd_srv_hello(a_tls_t *tls);
s32 a_tls13_snd_srv_ccs(a_tls_t *tls);
s32 a_tls_snd_enc_ext(a_tls_t *tls);
s32 a_tls13_snd_srv_cert(a_tls_t *tls);
s32 a_tls_nbio_flush(a_tls_t *tls);
s32 a_tls_snd_srv_vfy(a_tls_t *tls);
s32 a_tls13_snd_srv_finished(a_tls_t *tls);
s32 a_tls13_get_clnt_ccs(a_tls_t *tls);
s32 a_tls13_get_clnt_finished(a_tls_t *tls);
s32 a_tls13_snd_srv_ticket(a_tls_t *tls);
s32 a_tls_get_clnt_early_data(a_tls_t *tls);

s32 a_tls_gen_traffic_secret(a_tls_t *tls, a_md_t *md, u32 flag, u8 *traffic_secret);
void a_tls_gen_handshake_secret(a_tls_t *tls);
void a_tls13_gen_master_secret(a_tls_t *tls);
s32 a_tls_hkdf_expand_label(a_md_t *md,
    u8 *secret, s8 *label, u8 *hash, u32 hash_len, u8 *out, u32 out_len);
s32 a_tls_derive_finished(a_md_t *md, u8 *secret, u8 *out, u32 out_len);
s32 a_tls_derive_secret(a_md_t *md,
    u8 *secret, s8 *label, u8 *message, u32 message_len, u8 *out, u32 out_len);
s32 a_tls13_change_cipher_spec(a_tls_t *tls, u32 flag);

s32 a_tls13_dec(a_tls_t *tls, crypto_info_t *info)
{
    return tls->sess->cipher->dec(tls, info);
}

s32 a_tls13_enc(a_tls_t *tls, crypto_info_t *info)
{
    return tls->sess->cipher->enc(tls, info);
}

method_t tls13_spec =
{
    .enc = a_tls13_enc,
    .dec = a_tls13_dec,
    .change_cipher  = a_tls13_change_cipher_spec,
    .init_cipher    = a_tls13_init_cipher,
    .flag = A_CRYPTO_CIPHER_TLS1_3,
};


state_func tls13_state_proc[A_TLS_STATE_MAX] =
{
    [A_TLS_STATE_INIT]              = a_tls_init,
    [A_TLS_STATE_GET_CLNT_HELLO]    = a_tls_get_clnt_hello,
    [A_TLS_STATE_SND_SRV_HELLO]     = a_tls13_snd_srv_hello,
    [A_TLS_STATE_SND_SRV_CCS]       = a_tls13_snd_srv_ccs,
    [A_TLS_STATE_SND_ENC_EXT]       = a_tls_snd_enc_ext,
    [A_TLS_STATE_SND_SRV_CERT]      = a_tls13_snd_srv_cert,
    [A_TLS_STATE_SND_SRV_CERT_VFY]  = a_tls_snd_srv_vfy,
    [A_TLS_STATE_SND_SRV_FINISH]    = a_tls13_snd_srv_finished,
    [A_TLS_STATE_GET_CLNT_CCS]      = a_tls13_get_clnt_ccs,
    [A_TLS_STATE_GET_EARLY_DATA]    = a_tls_get_clnt_early_data,
    [A_TLS_STATE_GET_CLNT_FINISH]   = a_tls13_get_clnt_finished,
    [A_TLS_STATE_SND_NEW_TICKET]    = a_tls13_snd_srv_ticket,
    [A_TLS_STATE_WRITTING]          = a_tls_nbio_flush,
};


s32 a_tls_snd_enc_ext(a_tls_t *tls)
{
    u8 *p = a_tls_tmp_msg_buf, *l;
    s32 len;

    a_tls_gen_handshake_secret(tls);
    a_tls_change_cipher(tls, A_TLS_SECRET_WRITE|A_TLS_SECRET_HANDSHAKE);

    *p++ = A_TLS_MT_ENC_EXTENSION;
    l = p;
    p += 3;

    len = a_tls_construct_extension(tls, p + 2, A_TLS_MT_ENC_EXTENSION);
    s2n(len, p);
    p += len;

    len = (s32)(p - a_tls_tmp_msg_buf);
    l2n3((len - 4), l);

    if (tls->hit) {
        tls->state = A_TLS_STATE_SND_SRV_FINISH;

    } else {
        tls->state = A_TLS_STATE_SND_SRV_CERT;
    }

    return a_tls_snd_msg(tls, a_tls_tmp_msg_buf, (u32)len, A_TLS_RT_HANDHSHAKE);
}

void a_tls_get_vfy_tbs(a_tls_t *tls, a_md_t *md, u8* tbs, u32 *tbs_len)
{
    u8 *hs;
    u32 hs_len;
    s8 *servercontext = "TLS 1.3, server CertificateVerify";

    u8 *p = tbs;

    a_tls_get_hs_data(tls, &hs, &hs_len);

    memset(p, 0x20, 64);
    p += 64;
    memcpy(p, servercontext, 33);
    p += 33;
    *p ++ = 0;

    a_md_do_digest(md, hs, hs_len, p);
    p += md->hash_size;

    *tbs_len = (u32)(p - tbs);
}


s32 a_tls13_snd_srv_ticket(a_tls_t *tls)
{
    u8 *p = a_tls_tmp_msg_buf, *l;
    a_md_t *md;
    s8 nonce_label[]    = "resumption";
    u8 nonce[1]         = {0};/*should be a counter*/
    u32 len;

    *p++ = A_TLS_MT_SESS_TICKET;
    l = p;
    p += 3;

    /*
    struct {
        uint32 ticket_lifetime;
        uint32 ticket_age_add;
        opaque ticket_nonce<0..255>;
        opaque ticket<1..2^16-1>;
        Extension extensions<0..2^16-2>;
    } NewSessionTicket;
    */

    l2n(7200, p);
    l2n(100, p);

    /*ticket_nonce, 0, up to now*/
    *p ++ = 1;
    *p ++ = 0;

    /*The PSK associated with the ticket is computed as:
     *HKDF-Expand-Label(resumption_master_secret,
     *               "resumption", ticket_nonce, Hash.length)
     */
    md = tls->sess->md;
    a_tls_hkdf_expand_label(md, tls->handshake->resumption_master_secret,
        nonce_label, nonce, sizeof(nonce), tls->sess->master_secret, md->hash_size);

    /*For now master_secret is PSK*/

    a_tls_gen_session_ticket(tls, p + 2, &len);
    s2n(len, p);
    p += len;

    s2n(8, p);

    /*if we want to read early data*/
    if (tls->cfg->max_early_data) {
        /*extension*/
        s2n(0x002a, p);
        s2n(0x0004, p);
        l2n(tls->cfg->max_early_data, p);

    } else {
        s2n(0x0000, p);
    }

    len = (u32)(p - a_tls_tmp_msg_buf);
    l2n3((len - 4), l);

    tls->state = A_TLS_STATE_ESTABLISH;
    return a_tls_snd_msg(tls, a_tls_tmp_msg_buf, len, A_TLS_RT_HANDHSHAKE);
}

s32 a_tls_get_peer_finish(a_tls_t *tls, u8 *peer, u32 *peer_len)
{
    u8 *hs, hash[A_CRYPTO_MAX_MD_LEN];
    u32 hs_len;
    a_md_t *md = tls->sess->md;

    a_tls_get_hs_data(tls, &hs, &hs_len);
    a_md_do_digest(md, hs, hs_len, hash);
    a_crypto_hmac(md, tls->handshake->finishkey[0], md->hash_size, hash, md->hash_size, peer);
    *peer_len = md->hash_size;

    return A_TLS_OK;
}

s32 a_tls_get_clnt_early_data(a_tls_t *tls)
{
    s32 ret;
    msg_t msg;

    ret = a_tls_get_message(tls, &msg, A_TLS_RT_APPLICATION_DATA);
    if (ret != A_TLS_OK) {
        return ret;
    }

    /*We read the End Of Early Data packet*/
    if (msg.rt_type == A_TLS_RT_HANDHSHAKE) {
        a_tls_save_hs(tls, msg.data, msg.len);

        if (msg.len == 4
            && *msg.data == A_TLS_MT_END_ED)
        {
            a_tls_change_cipher(tls, A_TLS_SECRET_READ|A_TLS_SECRET_HANDSHAKE);
            tls->state = A_TLS_STATE_GET_CLNT_FINISH;
            return A_TLS_OK;

        } else {
            a_tls_error(tls, "clnt end of early data err");
            return A_TLS_ERR;
        }
    }

    if (tls->cfg->early_data_cb) {
        ret = tls->cfg->early_data_cb(tls, msg.data, msg.len);
        if (ret == A_TLS_OK) {
            a_tls_error(tls, "clnt early data cb err");
            return A_TLS_ERR;
        }
    }

    if (tls->early_data == NULL) {
        tls->early_data = a_tls_buf_new(tls->cfg->max_early_data);
        if (tls->early_data == NULL) {
            a_tls_error(tls, "clnt early data save err");
            return A_TLS_ERR;
        }
    }

    if (tls->early_data->last + msg.len > tls->early_data->end) {
        a_tls_error(tls, "clnt early data exceed last:%p end:%p add len:%d",
            tls->early_data->last, tls->early_data->end, msg.len);
        return A_TLS_ERR;
    }

    tls->early_data->last = memcpy(tls->early_data->last, msg.data, msg.len);
    tls->early_data->last += msg.len;

    {
        u32 k;
        printf("early_data:%d\n",msg.len);
        for(k=0;k<msg.len;k++)
        {
            printf("%02X", msg.data[k]);
        }
        printf("\n");
    }

    return A_TLS_OK;
}

s32 a_tls13_get_clnt_finished(a_tls_t *tls)
{
    u32 peer_len;
    s32 ret, len, remove_eoed = 0;
    u8 *p, peer[A_CRYPTO_MAX_MD_LEN];
    msg_t msg;

    ret = a_tls_get_message(tls, &msg, A_TLS_RT_HANDHSHAKE);
    if (ret != A_TLS_OK) {
        return ret;
    }

    p = msg.data;
    if (*p ++ != A_TLS_MT_FINISHED) {
        a_tls_error(tls, "clnt finished type error:%d", *(p-1));
        return A_TLS_ERR;
    }
    n2l3(p, len);

    if ((u32)len != msg.len - 4) {
        a_tls_error(tls, "clnt finished len error len:%d msg.len:%d", len, msg.len);
        return A_TLS_ERR;
    }


#ifdef TLS_DEBUG
    {
        u32 k;
        printf("a_tls13_get_clnt_finished %d\n",msg.len);
        for(k=0;k < msg.len;k++)
        {
            printf("%02X",msg.data[k]);
        }
        printf("\n");

    }
#endif
    a_tls_get_peer_finish(tls, peer, &peer_len);
    if (memcmp(peer, p ,peer_len)) {
        a_tls_error(tls, "check clnt finished error");
        return A_TLS_ERR;
    }

    a_tls13_gen_master_secret(tls);

    if (tls->hit
        && tls->ext.early_data == A_TLS_EARLY_DATA_ACCEPTED)
    {
        remove_eoed = 4;
    }

    tls->handshake->diget_off -= remove_eoed;
    /*read*/
    a_tls_change_cipher(tls, A_TLS_SECRET_READ|A_TLS_SECRET_APP);
    /*write*/
    a_tls_change_cipher(tls, A_TLS_SECRET_WRITE|A_TLS_SECRET_APP);
    tls->handshake->diget_off += remove_eoed;

    /*we have to save handshake to buf in order to calc res master secret
     *resumption_master_secret may be used to construct new session ticket
     */
    a_tls_save_hs(tls, msg.data, msg.len);
    a_tls_gen_traffic_secret(tls, tls->sess->md, A_TLS_SECRET_RESUME, tls->handshake->resumption_master_secret);

    tls->state = A_TLS_STATE_SND_NEW_TICKET;
    return A_TLS_OK;
}

s32 a_tls13_get_clnt_ccs(a_tls_t *tls)
{
    msg_t msg;
    s32 ret;

    ret = a_tls_get_message(tls, &msg, A_TLS_RT_CCS);
    if (ret != A_TLS_OK) {
        return ret;
    }

#ifdef TLS_DEBUG
    printf("a_tls13_get_clnt_ccs tls->hit:%d early:%d\n",tls->hit, tls->ext.early_data);
#endif
    if (tls->hit
        && tls->ext.early_data == A_TLS_EARLY_DATA_ACCEPTED)
    {
        //a_tls_change_cipher(tls, A_TLS_SECRET_READ|A_TLS_SECRET_EARLY);
        //move cc to parse clnt extension early, cause we need 'ClientHello' only.
        tls->state = A_TLS_STATE_GET_EARLY_DATA;

    } else {
        a_tls_change_cipher(tls, A_TLS_SECRET_READ|A_TLS_SECRET_HANDSHAKE);
        tls->state = A_TLS_STATE_GET_CLNT_FINISH;
    }

    return A_TLS_OK;
}

s32 a_tls13_snd_srv_finished(a_tls_t *tls)
{
    u8 *p = a_tls_tmp_msg_buf;
    u8 *hs,  digest[A_CRYPTO_MAX_MD_LEN];
    u32 hs_len;
    a_md_t *md = tls->sess->md;

    *p++ = A_TLS_MT_FINISHED;
    l2n3(md->hash_size, p);

    a_tls_get_hs_data(tls, &hs, &hs_len);
    a_md_do_digest(md, hs, hs_len, digest);
#ifdef TLS_DEBUG
    {
        u32 k;
        printf("hs digest len:%d\n",md->hash_size);
        for(k=0;k<md->hash_size;k++)
        {
            printf("%02X",digest[k]);
        }
        printf("\n");

        printf("finishkey:%d\n",md->hash_size);
        for(k=0;k<md->hash_size;k++)
        {
            printf("%2X",tls->handshake->finishkey[1][k]);
        }
        printf("\n");
    }
#endif
    a_crypto_hmac(md, tls->handshake->finishkey[1], md->hash_size, digest, md->hash_size, p);
    p += md->hash_size;

    tls->state = A_TLS_STATE_GET_CLNT_CCS;
    return a_tls_snd_msg(tls, a_tls_tmp_msg_buf, (u32)(p - a_tls_tmp_msg_buf), A_TLS_RT_HANDHSHAKE);
}

s32 a_tls_snd_srv_vfy(a_tls_t *tls)
{
    u8 *p = a_tls_tmp_msg_buf, *l;
    u8 tbs[64 + 33 + 1 + A_CRYPTO_MAX_MD_LEN];
    u32 tbs_len, len;
    sigalg_pair_t *sig;
    crypto_info_t info;
    a_md_t *md;
    void *key;

    *p++ = A_TLS_MT_CERTIFICATE_VERIFY;
    l = p;
    p += 3;

    sig = a_tls_select_sigalg(tls, &key, &md);
    s2n(sig->tls_id, p);

    a_tls_get_vfy_tbs(tls, tls->sess->md, tbs, &tbs_len);

#ifdef TLS_DEBUG
    {
        u32 k;
        printf("tbs:%d\n",tbs_len);
        for(k=0;k<tbs_len;k++)
        {
            printf("%02X", tbs[k]);
        }
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

    if (sig->sign(NULL, &info)
        != A_TLS_OK)
    {
        a_tls_error(tls, "srv vfy sign error");
        return A_TLS_ERR;
    }

    s2n(len, p);
    p += len;

    len = (u32)(p - a_tls_tmp_msg_buf);
    l2n3((len - 4), l);
    tls->state = A_TLS_STATE_SND_SRV_FINISH;
    return a_tls_snd_msg(tls, a_tls_tmp_msg_buf, len, A_TLS_RT_HANDHSHAKE);
}

s32 a_tls13_snd_srv_cert(a_tls_t *tls)
{
    s32 len, cert_indx = 0, i, tmp_len;
    u8 *p = a_tls_tmp_msg_buf, *l, *cl;

    *p++ = A_TLS_MT_CERT;
    l = p;
    p += 3;

    /*certificate request*/
    *p++ = 0;


    cl = p;
    p += 3;

    cert_indx = tls->selected_cert;
    for (i = 0; i < 10; i++) {

        if (tls->cfg->der[cert_indx][i] == NULL) {
            break;
        }

        tmp_len = tls->cfg->der_len[cert_indx][i];
        l2n3(tmp_len, p);
        memcpy(p ,tls->cfg->der[cert_indx][i], tmp_len);
        p += tmp_len;
        /*extension*/
        s2n(0 ,p);
    }

    len = (u32)(p - a_tls_tmp_msg_buf);
    l2n3((len - 4), l);
    l2n3((len - 4 - 4), cl);

    tls->state = A_TLS_STATE_SND_SRV_CERT_VFY;
    return a_tls_snd_msg(tls, a_tls_tmp_msg_buf, len, A_TLS_RT_HANDHSHAKE);
}

s32 a_tls13_snd_srv_hello(a_tls_t *tls)
{
    s32 len;
    u8 *p = a_tls_tmp_msg_buf, *l;

    *p++ = A_TLS_MT_SRV_HELLO;
    l = p;
    p += 3;

    len = a_tls_construct_srv_hello(tls, p);
    if (len <= 0) {
        a_tls_error(tls, "tls13 srv hello new error");
        return A_TLS_ERR;
    }

    p += len;
    len = a_tls_construct_extension(tls, p + 2, A_TLS_MT_SRV_HELLO);
    if (len < 0) {
        a_tls_error(tls, "tls13 srv hello ext new error");
        return A_TLS_ERR;
    }

    s2n(len, p);
    p += len;

    len = (u32)(p - a_tls_tmp_msg_buf);
    l2n3((len - 4), l);

    tls->state = A_TLS_STATE_SND_SRV_CCS;
    return a_tls_snd_msg(tls, a_tls_tmp_msg_buf, len, A_TLS_RT_HANDHSHAKE);
}

s32 a_tls13_change_cipher_spec(a_tls_t *tls, u32 flag)
{
    a_tls_derive_key_and_iv(tls, flag);
    a_tls13_init_cipher(tls, flag);
    return A_TLS_OK;
}

s32 a_tls13_snd_srv_ccs(a_tls_t *tls)
{
    u8 *p = a_tls_tmp_msg_buf;

    *p++ = 0x01;

    tls->state = A_TLS_STATE_SND_ENC_EXT;

    return a_tls_snd_msg(tls, a_tls_tmp_msg_buf, (u32)(p - a_tls_tmp_msg_buf), A_TLS_RT_CCS);
}


