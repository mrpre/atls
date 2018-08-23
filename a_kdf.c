#include "a_crypto.h"
#include "a_tls.h"

s32 a_crypto_HKDF_extract(a_md_t *md, u8 *salt, u32 salt_len, u8 *key, u32 key_len, u8 *out)
{
    const EVP_MD *md2;
    u32 outlen = 0;
    u8 zero[A_CRYPTO_MAX_MD_LEN] = {0};

    md2 = md->md;
    if (salt == NULL) {
        salt = zero;
        salt_len = md->hash_size;
    }

    if (key == NULL) {
        key = zero;
        key_len = md->hash_size;
    }

    if (!HMAC(md2, salt, salt_len, key, key_len, out, &outlen)) {
        return 1;
    }
    return 0;
}

s32 a_crypto_HKDF_expand(a_md_t *md, u8 *info, u32 info_len, u8 *key, u32 key_len, u8 *out, u32 out_len)
{
    const EVP_MD *md2;
    u32 ret, i, tmplen, tmp_out_len;
    u32 hash_size = md->hash_size;
    u8 *p, tmp[A_CRYPTO_MAX_MD_LEN]={0}, T[A_CRYPTO_MAX_MD_LEN]={0};

    md2 = md->md;
    /*calc the round times*/
    ret = out_len/hash_size + !!(out_len%hash_size);

    tmp_out_len = out_len;
    for (i = 0; i < ret; i++) {
        p = tmp;

        /*T(0) = empty string (zero length)*/
        if (i != 0) {
            memcpy(p, T, hash_size);
            p += hash_size;
        }

        memcpy(p, info, info_len);
        p += info_len;
        *p++ = i + 1;

        HMAC(md2, key, hash_size, tmp, (int)(p - tmp), T, &tmplen);
        memcpy(out + i*hash_size, T, (tmp_out_len < hash_size)?tmp_out_len:hash_size);
        tmp_out_len -= hash_size;
    }

#ifdef TLS_DEBUG
    {
        printf("HKDF expand out:%d\n",out_len);
        for(i=0;i<out_len;i++)
            printf("%02X", out[i]);
        printf("\n");
    }
#endif
    return 0;
}

s32 a_tls_hkdf_expand_label(a_md_t *md,
    u8 *secret, s8 *label, u8 *hash, u32 hash_len, u8 *out, u32 out_len)
{
    u8 HkdfLabel[2 + 1 + 255 + 1 + A_CRYPTO_MAX_MD_LEN];
    u8 *p;
    u32 label_len = strlen(label);
    p = HkdfLabel;
    s2n(out_len, p);
    *p++ = 6 + label_len;
    memcpy(p, "tls13 ", 6);
    p += 6;
    memcpy(p, label, label_len);
    p += label_len;

    *p++ = hash_len;
    memcpy(p, hash, hash_len);
    p += hash_len;

#ifdef TLS_DEBUG
    {
       u32 i;
       printf("hkdflabel %d\n",(u32)(p - HkdfLabel));
       for(i=0;i<(u32)(p - HkdfLabel);i++)
       {
           printf("%02X", HkdfLabel[i]);
       }
       printf("\n");

       printf("secret %d\n",md->hash_size);
       for(i=0;i<md->hash_size;i++)
       {
           printf("%02X", secret[i]);
       }
       printf("\n");
    }
#endif
    a_crypto_HKDF_expand(md, HkdfLabel, (u32)(p - HkdfLabel), secret, md->hash_size, out, out_len);
    return A_TLS_OK;
}

s32 a_tls_derive_secret(a_md_t *md,
    u8 *secret, s8 *label, u8 *message, u32 message_len, u8 *out, u32 out_len)
{
    u8 hash[A_CRYPTO_MAX_MD_LEN];
    u32 hash_len = md->hash_size;
    /*do Transcript-Hash(message)*/
    a_md_do_digest(md, message, message_len, hash);
#ifdef TLS_DEBUG
    {
        u32 i;
        printf("hash of mesage\n");
        for(i=0;i<hash_len;i++)
        {
            printf("%02X", hash[i]);
        }
        printf("\n");
    }
#endif
    a_tls_hkdf_expand_label(md, secret, label, hash, hash_len, out, out_len);
    return A_TLS_OK;
}

void a_tls13_gen_master_secret(a_tls_t *tls)
{
    a_md_t *md = tls->sess->md;
    a_tls_handshake_t *hs = tls->handshake;
    u32 md_size = md->hash_size;

#ifdef TLS_DEBUG
    {
        u32 i;
        printf("handshake_secret\n");
        for(i=0;i<md_size;i++)
        {
            printf("%02X", hs->handshake_secret[i]);
        }
        printf("\n");
    }
#endif
    /*Derive-Secret(., "derived", "")*/
    a_tls_derive_secret(md, hs->handshake_secret, "derived", NULL, 0, hs->pre_secret, md_size);

#ifdef TLS_DEBUG
    {
        u32 i;
        printf("hs->pre_secret\n");
        for(i=0;i<md_size;i++)
        {
            printf("%02X", hs->pre_secret[i]);
        }
        printf("\n");
    }
#endif
    /*1:HKDF-Extract*/
    a_crypto_HKDF_extract(md, hs->pre_secret, md_size, NULL, 0, tls->sess->master_secret);
#ifdef TLS_DEBUG
    {
        u32 i;
        printf("hs->master_secret\n");
        for(i=0;i<md_size;i++)
        {
            printf("%02X", tls->sess->master_secret[i]);
        }
        printf("\n");
    }
#endif
}

void a_tls_gen_handshake_secret(a_tls_t *tls)
{
    u8 pms[100];
    a_tls_handshake_t *hs = tls->handshake;
    a_md_t *md = tls->sess->md;
    u32 md_size = md->hash_size, pms_len;
    /*generate handshake secret*/

    /*We already calc the early_secret when we process the PSK extension*/
    if (!tls->hit) {
        /*1:HKDF-Extract*/
        a_crypto_HKDF_extract(md, NULL, 0, NULL, 0, hs->early_secret);
#ifdef TLS_DEBUG
        {
                u32 i;
                printf("early_secret\n");
                for(i=0;i<md_size;i++)
                {
                    printf("%02X", hs->early_secret[i]);
                }
                printf("\n");
        }
#endif
    }

    /*2:Derive-Secret(., "derived", "")*/
    a_tls_derive_secret(md, hs->early_secret, "derived", NULL, 0, hs->pre_secret, md_size);

    /*3:calc ecdhe secret*/
    hs = tls->handshake;
#ifdef NID_X25519
    if (hs->ecdh_id == A_CRYPTO_GROUP_ID_X25519) {
        a_crypto_calc_ec_shared_pkey(hs->ecdh_id, hs->self_pkey, hs->peer_pkey, pms, &pms_len);
    } else
#endif
    {
        a_crypto_calc_ec_shared(hs->group,
            hs->self_ecdh_prv,
            hs->self_ecdh_prv_len,
            hs->peer_ecdh_pub,
            hs->peer_ecdh_pub_len,
            pms, &pms_len);
    }
#ifdef TLS_DEBUG
    {
        u32 i;
        printf("pms\n");
        for(i=0;i<32;i++)
        {
            printf("%02X", pms[i]);
        }
        printf("\n");
    }
#endif
    a_crypto_HKDF_extract(md, hs->pre_secret, md_size, pms, pms_len, hs->handshake_secret);
#ifdef TLS_DEBUG
    {
        u32 i;
        printf("handshake secret\n");
        for(i=0;i<md_size;i++)
        {
            printf("%02X", hs->handshake_secret[i]);
        }
        printf("\n");
    }
#endif
}

/*
[sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
[sender]_write_iv  = HKDF-Expand-Label(Secret, "iv" , "", iv_length)
*/
s32 a_tls_derive_key(a_md_t *md, u8 *secret, u8 *out, u32 out_len)
{
    a_tls_hkdf_expand_label(md, secret, "key", (u8*)"", 0, out, out_len);
    return A_TLS_OK;
}

s32 a_tls_derive_iv(a_md_t *md, u8 *secret, u8 *out, u32 out_len)
{
    a_tls_hkdf_expand_label(md, secret, "iv", (u8*)"", 0, out, out_len);
    return A_TLS_OK;
}

s32 a_tls_derive_finished(a_md_t *md, u8 *secret, u8 *out, u32 out_len)
{
    a_tls_hkdf_expand_label(md, secret, "finished", (u8*)"", 0, out, out_len);
    return A_TLS_OK;
}

s32 a_tls_gen_traffic_secret(a_tls_t *tls, a_md_t *md, u32 flag, u8 *traffic_secret)
{
    s8 cli_el_traffic_label[] = "c e traffic";
    s8 srv_hs_traffic_label[] = "s hs traffic";
    s8 cli_hs_traffic_label[] = "c hs traffic";
    s8 srv_ap_traffic_label[] = "s ap traffic";
    s8 cli_ap_traffic_label[] = "c ap traffic";
    s8 res_master_label[]     = "res master";

    u8 hash[A_CRYPTO_MAX_MD_LEN], *secret = NULL, *hsdata;
    s8 *label = NULL;
    u32 hsdata_len;

    /*early data secret, only client write/server read*/
    if (flag&A_TLS_SECRET_EARLY) {
        label = cli_el_traffic_label;
        secret = tls->handshake->early_secret;

    } else if (flag&A_TLS_SECRET_RESUME) {
        /*session ticket's master secret*/
        label = res_master_label;
        secret = tls->sess->master_secret;

    } else if (flag&A_TLS_SECRET_READ) {
        /*server read schedule*/
        if (tls->dir) {

            if (flag&A_TLS_SECRET_HANDSHAKE) {
                label = cli_hs_traffic_label;
                secret = tls->handshake->handshake_secret;

            } else {
                label = cli_ap_traffic_label;
                secret = tls->sess->master_secret;
            }

        } else {
            //TO DO
        }

    } else if (flag&A_TLS_SECRET_WRITE) {
        /*server write schedule*/
        if (tls->dir) {
            if (flag&A_TLS_SECRET_HANDSHAKE) {
                label = srv_hs_traffic_label;
                secret = tls->handshake->handshake_secret;

            } else {
                label = srv_ap_traffic_label;
                secret = tls->sess->master_secret;
            }

        } else {
            //TO DO
        }
    }

    /*The Handshake guarantee the appropriate handshake data*/
    if (label == srv_ap_traffic_label
        || label == cli_ap_traffic_label
        || label == srv_hs_traffic_label
        || label == res_master_label
        || label == cli_el_traffic_label)
    {
        /*get the handshake*/
        a_tls_get_hs_data(tls, &hsdata, &hsdata_len);
        /*hash(ClientHello...server Finished)*/
        a_md_do_digest(md, hsdata, hsdata_len, hash);
    }

    if (label == srv_hs_traffic_label) {
        /*save hash(ClientHello...ServerHello) used by calc cli_hs_traffic*/
        memcpy(tls->handshake->handshake_secret_hash, hash, tls->sess->md->hash_size);

    } else if (label == cli_hs_traffic_label) {
        /*use the hash calced by srv_hs_traffic*/
        memcpy(hash, tls->handshake->handshake_secret_hash, tls->sess->md->hash_size);
    }
#ifdef TLS_DEBUG
    {
       u32 i;
       printf("hash of message %d\n",tls->sess->md->hash_size);
       for(i=0;i<tls->sess->md->hash_size;i++)
       {
           printf("%02X", hash[i]);
       }
       printf("\n");
    }
#endif
    a_tls_hkdf_expand_label(tls->sess->md, secret, label, hash, tls->sess->md->hash_size, traffic_secret, md->hash_size);

    //a_tls_derive_secret(md, secret, label, hsdata, hsdata_len, traffic_secret, md->hash_size);

    return A_TLS_OK;
}

s32 a_tls_derive_key_and_iv(a_tls_t *tls, u32 flag)
{
    u8 traffic_secret[A_CRYPTO_MAX_MD_LEN];
    a_cipher_t *cipher = tls->sess->cipher;
    a_md_t *md = tls->sess->md;
    u32 cidx = ((flag&A_TLS_SECRET_READ) == 0);

    a_tls_gen_traffic_secret(tls, md, flag, traffic_secret);
#ifdef TLS_DEBUG
   {
       u32 i;
       printf("traffic_secret %d\n",tls->sess->md->hash_size);
       for(i=0;i<md->hash_size;i++)
       {
           printf("%02X", traffic_secret[i]);
       }
       printf("\n");
    }
#endif
    a_tls_derive_key(md, traffic_secret, tls->key[cidx], cipher->key_len);
    a_tls_derive_iv(md, traffic_secret, tls->iv[cidx], cipher->iv_len);

    if (flag&A_TLS_SECRET_HANDSHAKE) {
        a_tls_derive_finished(md, traffic_secret, tls->handshake->finishkey[cidx], md->hash_size);
    }
    memset(tls->seq[cidx], 0, 8);
#ifdef TLS_DEBUG
    {
       u32 i;
       printf("key %d\n",cipher->key_len);
       for(i=0;i<cipher->key_len;i++)
       {
           printf("%02X", tls->key[cidx][i]);
       }
       printf("\n");

       printf("iv %d\n",cipher->iv_len);
       for(i=0;i<cipher->iv_len;i++)
       {
           printf("%02X", tls->iv[cidx][i]);
       }
       printf("\n");
    }
#endif
    return A_TLS_OK;
}

s32 a_crypto_phash(a_md_t *op, unsigned char *sec,
    int sec_len, u8 *seed, u32 seed_len, u8 *out, u32 olen)
{
	u8 *p = NULL, A1[A_CRYPTO_MAX_MD_LEN];
	s32 ret;

	p = a_tls_malloc(seed_len + op->hash_size);
	if(unlikely(NULL == p)) {
        goto err;
	}

	ret = a_crypto_hmac(op, sec, sec_len, seed, seed_len, A1);
	if(ret != A_TLS_OK) {
        goto err;
	}

    for (;;) {
		memcpy(p, A1, op->hash_size);
		memcpy(p + op->hash_size, seed, seed_len);

		if (olen > op->hash_size) {
			ret = a_crypto_hmac(op, sec, sec_len, p , seed_len + op->hash_size, out);
            if(ret != A_TLS_OK) {
				goto err;
			}

			out  += op->hash_size;
			olen -= op->hash_size;

			ret = a_crypto_hmac(op, sec, sec_len, A1, op->hash_size, A1);
            if(ret != A_TLS_OK) {
				goto err;
			}

        } else {
			ret = a_crypto_hmac(op, sec, sec_len, p, seed_len + op->hash_size, A1);
            if(ret != A_TLS_OK) {
				goto err;
			}

			memcpy(out, A1, olen);
			break;
		}
	}

    a_tls_free(p);
	return A_TLS_OK;
err:
    a_tls_free(p);
	return A_TLS_ERR;
}
