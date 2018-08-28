#include "a_crypto.h"
#include "a_tls.h"

s32 a_tls_ext_parse_renegotiation(a_tls_t *tls, u8 *ext, u32 ext_len)
{
    u8 *p = ext;
    u16 len;

    len = *p++;

    if (len != 0) {
        /*we do not support secure renegotiation*/
        return A_TLS_OK;
    }

    tls->ext.bind = 1;
    return A_TLS_OK;
}
s32 a_tls_ext_parse_ks(a_tls_t *tls, u8 *ext, u32 ext_len)
{
    u8 *p = ext;
    u16 ks_len, ke_len, groupid;

    n2s(p, ks_len);

    if (ks_len != ext_len - 2) {
        a_tls_error(tls, "tls ext key share len err ks_len:%d ext_len:%d", ks_len, ext_len);
        return A_TLS_ERR;
    }

    while(p < ext + ext_len) {
        n2s(p, groupid);
        n2s(p, ke_len);

        tls->group = tls->handshake->group = a_crypto_get_group_by_tls_id(groupid);
        if (tls->handshake->group != NULL) {

#ifdef NID_X25519
            if (groupid == A_CRYPTO_GROUP_ID_X25519) {
                tls->handshake->peer_pkey = a_crypto_gen_pkey(tls->handshake->group, p, ke_len);
                if (tls->handshake->peer_pkey == NULL) {
                    a_tls_error(tls, "tls ext key share x25519 gen err");
                    return A_TLS_ERR;
                }
                tls->handshake->ecdh_id = groupid;
                break;
            }
#endif
            tls->handshake->peer_ecdh_pub = a_tls_malloc(ke_len);
            if (tls->handshake->peer_ecdh_pub == NULL) {
                a_tls_error(tls, "tls ext key share pub new err");
                return A_TLS_ERR;
            }
            memcpy(tls->handshake->peer_ecdh_pub, p, ke_len);
            tls->handshake->ecdh_id = groupid;
            tls->handshake->peer_ecdh_pub_len = ke_len;
            break;
        }
        p += ke_len;
    }

    /*we cant't support client's keyshare, send Hello request*/
    if (tls->handshake->group == NULL
        || tls->handshake->peer_pkey == NULL) {
    }

    return A_TLS_OK;
}

s32 a_tls_ext_gen_session_ticket(a_tls_t *tls, u8 *ext, u32 type)
{
    u8 *p = ext;

    if (tls->hit
        || type != A_TLS_MT_SRV_HELLO
        || !tls->ext.sess_tikcet)
    {
        return 0;
    }

    s2n(A_TLS_EXT_SESS_TICKET, p);
    s2n(0x00, p);
    return 4;
}

s32 a_tls_ext_gen_psk(a_tls_t *tls, u8 *ext, u32 type)
{
    u8 *p = ext;

    if (type != A_TLS_MT_SRV_HELLO
        || !tls->hit)
    {
        return 0;
    }

    s2n(A_TLS_EXT_PSK, p);
    s2n(0x0002, p);
    s2n(tls->ext.psk_idx, p);
    return (s32)(p - ext);
}

s32 a_tls_ext_gen_renegotiation(a_tls_t *tls, u8 *ext, u32 type)
{
    u8 *p = ext;

    if (type != A_TLS_MT_SRV_HELLO) {
        return 0;
    }

    if (tls->ext.bind) {
        s2n(A_TLS_EXT_RENEGO, p);
        s2n(0x0001, p);
        *p++ = 0x00;
    }
    return (s32)(p - ext);
}
s32 a_tls_ext_gen_ks(a_tls_t *tls, u8 *ext, u32 type)
{
    a_tls_handshake_t *hs = tls->handshake;
    u8 *p = ext;

    if (type != A_TLS_MT_SRV_HELLO) {
        return 0;
    }

#ifdef NID_X25519
    u32 len;
    if (hs->group->tls_nid == A_CRYPTO_GROUP_ID_X25519) {
        s2n(A_TLS_EXT_KEY_SHARE, p);

        hs->self_pkey = a_crypto_gen_ec_pub_pkey(hs->group,
                                                     p + 6, &len);
        if (hs->self_pkey == NULL) {
            a_tls_error(tls, "tls ext key share x25519 pub gen err");
            return A_TLS_ERR;
        }
        s2n(len + 4, p);
        s2n(hs->ecdh_id, p);
        s2n(len, p);
        p += len;
        return (s32)(p - ext);
    }
#endif
    if (a_crypto_gen_ec_pub(hs->group,
             &hs->self_ecdh_prv, &hs->self_ecdh_pub,
             &hs->self_ecdh_prv_len, &hs->self_ecdh_pub_len))
    {
        a_tls_error(tls, "tls ext key share pub gen err");
        return A_TLS_ERR;
    }

    s2n(A_TLS_EXT_KEY_SHARE, p);
    s2n(hs->self_ecdh_pub_len + 4, p);

    s2n(hs->ecdh_id, p);
    s2n(hs->self_ecdh_pub_len, p);
    memcpy(p, hs->self_ecdh_pub, hs->self_ecdh_pub_len);
    p += hs->self_ecdh_pub_len;

    return (s32)(p - ext);
}

s32 a_tls_process_binders(a_tls_t *tls, a_tls_sess_t *sess, s32 idx, u8 *binders, u16 binders_len)
{
    s32 i = 0;
    u32 hs_len;
    s8 binder_label[]   = "res binder";
    u8 hash[A_CRYPTO_MAX_MD_LEN];
    u8 binder_key[A_CRYPTO_MAX_MD_LEN];
    u8 finish_key[A_CRYPTO_MAX_MD_LEN];
    u8 binder_len, *binder, *hs;

    a_md_t * md = sess->md;

    binder = binders;
    while((s16)binders_len > 0) {
        binder_len = *binder++;
        if (idx == i) {
            break;
        }
        binders_len -= binder_len + 1;
        i++;
    }

    if ((s16)binders_len <= 0) {
        a_tls_error(tls, "tls13 binders len error1:%d",binders_len);
        return A_TLS_ERR;
    }

    if (binder_len != md->hash_size) {
        a_tls_error(tls, "tls13 binders len error2:%d", binder_len);
        return A_TLS_ERR;
    }

    /*Generate early_secret, psk is the secret, salt is null*/
    a_crypto_HKDF_extract(md, NULL, 0, sess->master_secret, md->hash_size, tls->handshake->early_secret);

    /*Generate binder key*/
    a_tls_derive_secret(md, tls->handshake->early_secret, binder_label, NULL, 0, binder_key, md->hash_size);

    /*
    The PskBinderEntry is computed in the same way as the Finished
    message but with the BaseKey being the binder_key
    derived via the key schedule from the corresponding PSK which is
    being offered.
    */
    a_tls_derive_finished(md, binder_key, finish_key, md->hash_size);
#ifdef TLS_DEBUG
    {
        u32 k;
        printf("old master secret %d\n",md->hash_size);
        for(k=0;k < md->hash_size;k++)
        {
            printf("%02X",sess->master_secret[k]);
        }
        printf("\n");

    }

    {
        u32 k;
        printf("new early_secret:%d\n",md->hash_size);
        for(k=0;k < md->hash_size;k++)
        {
            printf("%02X",tls->handshake->early_secret[k]);
        }
        printf("\n");

    }

    {
        u32 k;
        printf("new binder_key:%d\n",md->hash_size);
        for(k=0;k < md->hash_size;k++)
        {
            printf("%02X",binder_key[k]);
        }
        printf("\n");

    }
    {
        u32 k;
        printf("new finish_key:%d\n",md->hash_size);
        for(k=0;k < md->hash_size;k++)
        {
            printf("%02X",finish_key[k]);
        }
        printf("\n");
    }
#endif
    /*
    Each entry in the binders list is computed as an HMAC
    over a transcript hash (see Section 4.4.1) containing a partial
    ClientHello up to and including the PreSharedKeyExtension.identities
    field.  That is, it includes all of the ClientHello but not the
    binders list itself.
    */
    a_tls_get_hs_data(tls, &hs, &hs_len);
    a_md_do_digest(md, hs, hs_len - binders_len - 2, hash);

    a_crypto_hmac(md, finish_key, md->hash_size, hash, md->hash_size, hash);

    if (memcmp(hash, binder, binder_len)) {
        a_tls_error(tls, "check binder err");
        return A_TLS_ERR;
    }

    /*check binders success*/
    tls->sess = sess;
    tls->ext.psk_idx = idx;

    return A_TLS_OK;
}

s32 a_tls_ext_gen_early_data(a_tls_t *tls, u8 *ext, u32 type)
{
    u8 *p = ext;

    if (type != A_TLS_MT_ENC_EXTENSION) {
        return 0;
    }

    if (tls->hit
        && tls->ext.early_data == A_TLS_EARLY_DATA_ACCEPTED)
    {
        s2n(A_TLS_EXT_EARLY_DATA, p);
        s2n(0x00, p);
    }
    //else we don't want to process early data
    return (s32)(p - ext);
}

s32 a_tls_ext_parse_early_data(a_tls_t *tls, u8 *ext, u32 ext_len)
{
    if (ext_len != 0) {
        a_tls_error(tls, "tls ext early data len err:%d", ext_len);
        return A_TLS_ERR;
    }

    if(tls->ext.psk_idx == 0) {
        /*only psk handshake is using then set it to accept*/
        tls->ext.early_data = A_TLS_EARLY_DATA_ACCEPTING;
    }

    return A_TLS_OK;
}

s32 a_tls_ext_parse_session_ticket(a_tls_t *tls, u8 *ext, u32 ext_len)
{
    a_tls_sess_t *sess = NULL;
    u8 *p = ext;

    tls->ext.sess_tikcet = 1;

    /*client support session ticket*/
    if (ext_len == 0) {
        return A_TLS_OK;
    }

    /*client pad ticket, we try to parse it*/
    a_tls_parse_session_ticket(tls, p, ext_len, &sess);
    tls->sess = sess;
    return A_TLS_OK;
}

s32 a_tls_ext_parse_psk(a_tls_t *tls, u8 *ext, u32 ext_len)
{
    a_tls_sess_t *sess = NULL;
    s32 ret;
    u32 age, idx = 0;
    u16 ids_len, id_len ,binders_len;
    u8 *p = ext, *binders;

    n2s(p, ids_len);
    binders = p + ids_len;

    /*get identity*/
    while((s16)ids_len > 0 && idx < 10) {
        //TO DO, To protect against Replay-Attack we need to do some restrictions.
        n2s(p, id_len);
        a_tls_parse_session_ticket(tls, p, id_len, &sess);
        p += id_len;
        n2l(p, age);
        if(sess) {
            /*
            Servers SHOULD NOT attempt to validate multiple binders;
            rather they SHOULD select a single PSK and validate solely the binder
            that corresponds to that PSK.
            */
            break;
        }
        ids_len -= 2 + id_len + 4;
        idx++;
    }

    if (sess == NULL) {
        return A_TLS_OK;
    }

    /*TODO:
        we need to check reply
    */
    if (ids_len == 0 && p != binders) {
        return A_TLS_OK;
    }

    p = binders;
    n2s(p, binders_len);

    ret = a_tls_process_binders(tls, sess, idx, p, binders_len);
    if (ret != A_TLS_OK) {
        return ret;
    }

    return A_TLS_OK;
}

s32 a_tls_ext_parse_support_ver(a_tls_t *tls, u8 *ext, u32 ext_len)
{
    u8 *p = ext;
    u16 sv_len, version;

    sv_len = *p++;

    if (sv_len != ext_len - 1) {
        a_tls_error(tls, "tls ext version len err sv_len:%d ext_len:%d", sv_len, ext_len);
        return A_TLS_ERR;
    }

    while(p < ext + ext_len) {
        n2s(p, version);

        if (version == A_TLS_TLS_1_3_VERSION) {
            tls->version = A_TLS_TLS_1_3_VERSION;
            tls->handshake_version = A_TLS_TLS_1_2_VERSION;
            tls->state_proc = tls13_state_proc;
            tls->spec = &tls13_spec;
        }
    }
    return A_TLS_OK;
}

s32 a_tls_ext_gen_support_ver(a_tls_t *tls, u8 *ext, u32 type)
{
    u8 *p = ext;

    if (type != A_TLS_MT_SRV_HELLO) {
        return 0;
    }

    s2n(A_TLS_EXT_SUPPORT_VER, p);
    s2n(2, p);
    s2n(tls->version, p);
    return (s32)(p - ext);
}

s32 a_tls_ext_parse_support_gp(a_tls_t *tls, u8 *ext, u32 ext_len)
{
    u16 sg_len, i, group_id;
    u8 *p = ext, *save_curve;
    u8 index;

    n2s(p, sg_len);

    if(unlikely(sg_len&0x1)) {
        a_tls_error(tls, "tls ext group len err sg_len:%d", sg_len);
        return A_TLS_ERR;
    }

    if(unlikely(sg_len != ext_len - 2)) {
        a_tls_error(tls, "tls ext group len err sg_len:%d ext_len:%d", sg_len, ext_len);
        return A_TLS_ERR;
    }

    save_curve = tls->handshake->clnt_curve;
    for(i = 0; i < sg_len; i += 2) {
        n2s(p, group_id);

        if (group_id == A_CRYPTO_GROUP_ID_X25519) {
            continue;
        }

        index = a_crypto_get_group_index_by_tls_id(group_id);
        if (index == 0) {
            continue;
        }

        *save_curve++ = index;
    }
    return A_TLS_OK;
}

s32 a_tls_ext_parse_sig(a_tls_t *tls, u8 *ext, u32 ext_len)
{
    u16 sigs_len, sig_nid;
    u8 *p = ext, *save_sig;

    n2s(p, sigs_len);

    if (p + sigs_len != ext + ext_len) {
        a_tls_error(tls, "tls ext sig len err sigs_len:%d ext_len:%d", sigs_len, ext_len);
        return A_TLS_ERR;
    }

    if (sigs_len&1) {
        a_tls_error(tls, "tls ext sig len err sigs_len:%d", sigs_len);
        return A_TLS_ERR;
    }

    save_sig = tls->handshake->clnt_sig;
    while(p < ext + ext_len)
    {
        n2s(p, sig_nid);

        s8 index = a_tls_get_sigalg_index(sig_nid);
        if (index < 0) {
            continue;
        }

        *save_sig++ = index;
    }

    return A_TLS_OK;
}

s32 a_tls_parse_session_ticket(a_tls_t *tls, u8 *ticket, u32 ticket_len, a_tls_sess_t **sess)
{
    a_tls_sess_t *ret;
    u16 cipher_nid, sni_len;

    ret = a_tls_malloc(sizeof(a_tls_sess_t));
    if (ret == NULL) {
        a_tls_error(tls, "tls parse new ticket err");
        return A_TLS_ERR;
    }

    memset(ret, 0 ,sizeof(a_tls_sess_t));

    n2s(ticket, cipher_nid);
    ticket_len -= 2;

    ret->cipher = a_crypto_find_cipher_by_nid(cipher_nid);
    if (ret->cipher == NULL) {
        a_tls_error(tls, "tls parse new ticket cipher err");
        return A_TLS_ERR;
    }

    ret->md = ret->cipher->md;

    memcpy(ret->master_secret, ticket, A_TLS_MASTER_KEY_LEN);
    ticket += A_TLS_MASTER_KEY_LEN;
    ticket_len -= A_TLS_MASTER_KEY_LEN;

    n2s(ticket, sni_len);
    if (sni_len) {
        ret->sni = a_tls_malloc(sni_len);
        if (ret->sni == NULL) {
            a_tls_free_sess(ret);
        }
        memcpy(ret->sni, ticket, sni_len);
        ret->sni_len = sni_len;
        ticket += sni_len;
        ticket_len -= sni_len;
    }

    *sess = ret;
    return A_TLS_OK;
}

s32 a_tls_gen_session_ticket(a_tls_t *tls, u8 *out, u32 *out_len)
{
    a_tls_sess_t *sess = tls->sess;
    u8 *p = out;

    s2n(sess->cipher->tls_nid, p);

    memcpy(p, sess->master_secret, A_TLS_MASTER_KEY_LEN);
    p += A_TLS_MASTER_KEY_LEN;

    s2n(sess->sni_len, p);
    if (sess->sni) {
        memcpy(p, sess->sni, sess->sni_len);
        p += sess->sni_len;
    }

    /*TODO:
     *client certificate
     */

    *out_len = (u32)(p - out);
    return A_TLS_OK;
}

s32 a_tls_ext_parse_sni(a_tls_t *tls, u8 *ext, u32 ext_len)
{
    u8 *p = ext;
    u16 list_len, sn_len;

    n2s(p, list_len);

    if (list_len != ext_len - 2) {
        a_tls_error(tls, "tls parse sni len err, list_len:%d ext_len:%d", list_len, ext_len);
        return A_TLS_ERR;
    }

    while (p < ext + ext_len) {
        if (*p++ == 0) {
            n2s(p, sn_len);
            if (sn_len > 255) {
                a_tls_error(tls, "tls parse sni len to long:%d", sn_len);
                return A_TLS_ERR;
            }

            tls->handshake->sni = a_tls_malloc(sn_len);
            if (tls->handshake->sni == NULL) {
                a_tls_error(tls, "tls parse sni new err");
                return A_TLS_ERR;
            }

            memcpy(tls->handshake->sni, p, sn_len);
            tls->handshake->sni_len = sn_len;
            break;
        }
    }

    return A_TLS_OK;
}

ext_func_t ext_proc[A_TLS_EXT_MAX] =
{
    [A_TLS_EXT_SRV_NAME]   = {a_tls_ext_parse_sni, NULL, A_TLS_EXT_SUPPORT_GP, A_TLS_VERSION_ALL},
    [A_TLS_EXT_SUPPORT_GP] = {a_tls_ext_parse_support_gp, NULL, A_TLS_EXT_SIG_ALG, A_TLS_VERSION_ALL},
    [A_TLS_EXT_SIG_ALG]    = {a_tls_ext_parse_sig, NULL, A_TLS_EXT_SESS_TICKET, A_TLS_VERSION_ALL},
    [A_TLS_EXT_SESS_TICKET]= {a_tls_ext_parse_session_ticket, a_tls_ext_gen_session_ticket, A_TLS_EXT_PSK, A_TLS_VERSION_ALL_OLD},
    [A_TLS_EXT_PSK]        = {a_tls_ext_parse_psk, a_tls_ext_gen_psk, A_TLS_EXT_EARLY_DATA, A_TLS_1_3},
    [A_TLS_EXT_EARLY_DATA] = {a_tls_ext_parse_early_data, a_tls_ext_gen_early_data, A_TLS_EXT_SUPPORT_VER, A_TLS_1_3},
    [A_TLS_EXT_SUPPORT_VER]= {a_tls_ext_parse_support_ver, a_tls_ext_gen_support_ver, A_TLS_EXT_PSK_MODE, A_TLS_1_3},
    [A_TLS_EXT_PSK_MODE]   = {NULL, NULL, A_TLS_EXT_ALG_CERT, A_TLS_1_3},
    [A_TLS_EXT_ALG_CERT]   = {NULL, NULL, A_TLS_EXT_KEY_SHARE, A_TLS_1_3},
    [A_TLS_EXT_KEY_SHARE]  = {a_tls_ext_parse_ks, a_tls_ext_gen_ks, A_TLS_EXT_RENEGO, A_TLS_1_3},
    [A_TLS_EXT_RENEGO]     = {a_tls_ext_parse_renegotiation, a_tls_ext_gen_renegotiation, A_TLS_EXT_MAX, A_TLS_VERSION_ALL_OLD},
};

s32 a_tls_parse_extension(a_tls_t *tls, u8 *ext, s16 ext_len)
{
    u16 len = 0;
    u16 ext_type;

    while(ext_len > 0) {
        n2s(ext, ext_type);
        ext_len -= 2;
        n2s(ext, len);

        if(likely(ext_type < A_TLS_EXT_MAX
            && ext_proc[ext_type].parse))
        {
            ext_proc[ext_type].parse(tls, ext, len);
        }
        ext += len;
        ext_len -= 2 + len;
    }

    /*post work*/

    return A_TLS_OK;
}

s32 a_tls_construct_extension(a_tls_t *tls, u8 *buf, u32 type)
{
    u8 *p = buf;
    s32 ret;
    u32 i;

    for (i = A_TLS_EXT_SRV_NAME; i < A_TLS_EXT_MAX;) {
        if (ext_proc[i].gen
            && (tls->flag & ext_proc[i].flag))
        {
            ret = ext_proc[i].gen(tls, p, type);
            if (ret < 0) {
                return ret;
            }
            p += ret;
        }

        i = ext_proc[i].next;
    }

    return (s32)(p - buf);
}

