#ifndef _A_TLS_H_INCLUDED_
#define _A_TLS_H_INCLUDED_
#include "a_core.h"
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define n2s(c,s)	((s=(((unsigned int)(c[0]))<< 8)| \
			    (((unsigned int)(c[1]))    )),c+=2)
#define s2n(s,c)	((c[0]=(unsigned char)(((s)>> 8)&0xff), \
			  c[1]=(unsigned char)(((s)    )&0xff)),c+=2)
#define n2l(c,l)	(l =((unsigned long)(*((c)++)))<<24, \
                 l|=((unsigned long)(*((c)++)))<<16, \
                 l|=((unsigned long)(*((c)++)))<< 8, \
                 l|=((unsigned long)(*((c)++))))

#define l2n(l,c)	(*((c)++)=(unsigned char)(((l)>>24)&0xff), \
                 *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                 *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                 *((c)++)=(unsigned char)(((l)    )&0xff))
#define n2l3(c,l)	((l =(((unsigned long)(c[0]))<<16)| \
                     (((unsigned long)(c[1]))<< 8)| \
                     (((unsigned long)(c[2]))    )),c+=3)

#define l2n3(l,c)	((c[0]=(unsigned char)(((l)>>16)&0xff), \
                  c[1]=(unsigned char)(((l)>> 8)&0xff), \
                  c[2]=(unsigned char)(((l)    )&0xff)),c+=3)

#define a_tls_error(__tls, __str, __args...) \
do\
{\
    a_tls_err_t *__err = a_tls_malloc(sizeof(a_tls_err_t) + 100);\
    if (__err == NULL) {\
        break;\
    }\
    __err->str_len = snprintf(__err->str, 100, __str, ##__args);\
    __err->next = __tls->err_stack;\
    __tls->err_stack = __err;\
}while(0);\

#define A_TLS_OK            0
#define A_TLS_LACK          1
#define A_TLS_WANT_READ     -1
#define A_TLS_WANT_WRITE    -2
#define A_TLS_ERR           -3
#define A_TLS_CONTINUE      -4
#define A_TLS_WRITE_NBIO    -5
#define A_TLS_READ_FIN      -6

#define A_TLS_READ_HEAD     0
#define A_TLS_READ_BODY     1
#define A_TLS_HEAD_LEN      5
#define A_TLS_RAND_SIZE     32
#define A_TLS_SESS_ID_SIZE  32
#define A_TLS_MAX_CACHE_BUF (16384 + A_TLS_HEAD_LEN)
#define A_TLS_MAX_SIG_ALG   32
#define A_TLS_MAX_GROUP     32
#define A_TLS_MASTER_KEY_LEN                48
#define A_TLS_PRE_MASTER_KEY_LEN            48
#define A_TLS_MASTER_SECRET_CONST		    "master secret"
#define A_TLS_MASTER_SECRET_CONST_LEN       13
#define A_TLS_KEY_EXPANSION_CONST		    "key expansion"
#define A_TLS_KEY_EXPANSION_CONST_LEN		13
#define A_TLS_MD_MAX_CONST_SIZE			    20
#define A_TLS_MD_CLIENT_FINISH_CONST        "client finished"
#define A_TLS_MD_CLIENT_FINISH_CONST_SIZE   15
#define A_TLS_MD_SERVER_FINISH_CONST        "server finished"
#define A_TLS_MD_SERVER_FINISH_CONST_SIZE   15
#define A_TLS_MASTER_KEY_BUF_LEN            (A_TLS_MASTER_SECRET_CONST_LEN + A_TLS_RAND_SIZE*2)
#define A_TLS_MAX_KB_LABEL_LEN              (A_TLS_KEY_EXPANSION_CONST_LEN + A_TLS_RAND_SIZE*2)

enum
{
    A_TLS_EARLY_DATA_NONE   = 0,/*default*/
    A_TLS_EARLY_DATA_REJECT,    /*we should drop it*/
    A_TLS_EARLY_DATA_ACCEPTING, /*middle state*/
    A_TLS_EARLY_DATA_ACCEPTED,  /*we would read early data*/
};

/*ccs flag*/
enum
{
    A_TLS_SECRET_READ       = (1<<0),
    A_TLS_SECRET_WRITE      = (1<<1),

    A_TLS_SECRET_HANDSHAKE  = (1<<2),
    A_TLS_SECRET_APP        = (1<<3),
    A_TLS_SECRET_RESUME     = (1<<4),
    A_TLS_SECRET_EARLY      = (1<<5),
    A_TLS_SECRET_CLNT       = (1<<6),
    A_TLS_SECRET_SRV        = (1<<7),
};

#define A_TLS_SECRET_RW_MASK 1

enum
{
    A_TLS_ECDSA_256             = 0x0403,
    A_TLS_ECDSA_384             = 0x0503,
    A_TLS_ECDSA_512             = 0x0603,

    A_TLS_RSAPSS_RSAE_SHA256    = 0x0804,
    A_TLS_RSAPSS_RSAE_SHA384    = 0x0805,
    A_TLS_RSAPSS_RSAE_SHA512    = 0x0806,

    /*ed*/
    A_TLS_ED25519               = 0x0807,
    A_TLS_ED448                 = 0x0808,

    A_TLS_RSAPSS_PSS_SHA256     = 0x0809,
    A_TLS_RSAPSS_PSS_SHA384     = 0x080a,
    A_TLS_RSAPSS_PSS_SHA512     = 0x080b,


    /*old*/
    A_TLS_EXT_RSA_SHA1          = 0x0201,
    A_TLS_EXT_RSA_SHA256        = 0x0401,
    A_TLS_EXT_RSA_SHA384        = 0x0501,
    A_TLS_EXT_RSA_SHA512        = 0x0601,

    A_TLS_EXT_ECDSA_SHA1        = 0x0203,
    //A_TLS_EXT_ECDSA_SHA224      = 0x0303,
    A_TLS_EXT_ECDSA_SHA256      = 0x0403,
    A_TLS_EXT_ECDSA_SHA384      = 0x0503,
    A_TLS_EXT_ECDSA_SHA512      = 0x0603,
};

enum
{
    A_TLS_GM                = (1<<0),
    A_TLS_1_0               = (1<<1),
    A_TLS_1_1               = (1<<2),
    A_TLS_1_2               = (1<<3),
    A_TLS_1_3               = (1<<4),
    A_TLS_VERSION_ALL_OLD   = A_TLS_1_0|A_TLS_1_1|A_TLS_1_2,
    A_TLS_VERSION_ALL       = A_TLS_VERSION_ALL_OLD|A_TLS_1_3,
};

enum
{
    A_TLS_GM_VERSION      = 0x0101,/*GM/T*/
    A_TLS_VERSION_MIN     = 0x0300,/*SSL 3.0 */
    A_TLS_TLS_1_0_VERSION = 0x0301,/*TLS 1.0*/
    A_TLS_TLS_1_1_VERSION = 0x0302,/*TLS 1.1*/
    A_TLS_TLS_1_2_VERSION = 0x0303,/*TLS 1.2*/
    A_TLS_TLS_1_3_DRAFT_VERSION = 0x7f1a,/*draft*/
    A_TLS_TLS_1_3_VERSION = A_TLS_TLS_1_3_DRAFT_VERSION,
    A_TLS_VERSION_MAX
};
#define IS_TLS13(tls)   (tls->version == A_TLS_TLS_1_3_VERSION)
#define IS_TLSGM(tls)   (tls->version == A_TLS_GM_VERSION)

enum {
    A_TLS_MT_CLNT_HELLO          = 0x01,
    A_TLS_MT_SRV_HELLO           = 0x02,
    A_TLS_MT_SESS_TICKET         = 0x04,
    A_TLS_MT_END_ED              = 0x05,
    A_TLS_MT_ENC_EXTENSION       = 0x08,
    A_TLS_MT_CERT                = 0x0b,
    A_TLS_MT_SRV_KEYEXCHANGE     = 0x0c,
    A_TLS_MT_SRV_CERT_REQ        = 0x0d,
    A_TLS_MT_SRV_DONE            = 0x0e,
    A_TLS_MT_CERTIFICATE_VERIFY  = 0x0f,
    A_TLS_MT_CLNT_KEYEXCHANGE    = 0x10,
    A_TLS_MT_FINISHED            = 0x14
};

enum {
    A_TLS_STATE_INIT,
    A_TLS_STATE_GET_CLNT_HELLO,
    A_TLS_STATE_SND_SRV_HELLO,
    A_TLS_STATE_SND_SRV_KE,
    A_TLS_STATE_SND_SRV_DONE,
    A_TLS_STATE_SND_SRV_CCS,//5
    A_TLS_STATE_SND_SRV_TICKET,
    A_TLS_STATE_SND_ENC_EXT,
    A_TLS_STATE_SND_SRV_CERT,
    A_TLS_STATE_SND_SRV_CERT_VFY,
    A_TLS_STATE_SND_SRV_FINISH,
    A_TLS_STATE_GET_CLNT_CCS,//11
    A_TLS_STATE_GET_CLNT_CKE,
    A_TLS_STATE_GET_EARLY_DATA,
    A_TLS_STATE_GET_CLNT_FINISH,
    A_TLS_STATE_SND_NEW_TICKET,
    A_TLS_STATE_ESTABLISH,
    A_TLS_STATE_WRITTING,
    A_TLS_STATE_MAX
};

enum {
    A_TLS_EXT_SRV_NAME   = 0x0000,
    A_TLS_EXT_STATUS_REQ = 0x0005,
    A_TLS_EXT_ALPN       = 0x0010,
    A_TLS_EXT_SUPPORT_GP = 0x000a,
    A_TLS_EXT_ECC_FORMAT = 0x000b,
    A_TLS_EXT_SIG_ALG    = 0x000d,
    A_TLS_EXT_SCTT       = 0x0012,
    A_TLS_EXT_ETM        = 0x0016,
    A_TLS_EXT_EMS        = 0x0017,
    A_TLS_EXT_SESS_TICKET= 0x0023,
    A_TLS_EXT_PSK        = 0x0029,
    A_TLS_EXT_EARLY_DATA = 0x002a,
    A_TLS_EXT_SUPPORT_VER= 0x002b,
    A_TLS_EXT_PSK_MODE   = 0x002d,
    A_TLS_EXT_ALG_CERT   = 0x0032,
    A_TLS_EXT_KEY_SHARE  = 0x0033,
    A_TLS_EXT_RENEGO     = 0xff01,
    A_TLS_EXT_MAX,
};

enum
{
    A_TLS_RT_CCS = 0x14,
    A_TLS_RT_ALERT = 0x15,
    A_TLS_RT_HANDHSHAKE = 0x16,
    A_TLS_RT_APPLICATION_DATA = 0x17
};

typedef struct {
    u8 *pos;
    u8 *last;
    u8 *end;
    u8 start[0];
}a_tls_buf_t;

typedef struct {
    u8 type;
    u16 version;
    u16 len;
}a_tls_record_t;

typedef struct {
    u8 *key_block;
    u32 key_block_len;
    void *self_pkey;
    void *peer_pkey;
    u8 *peer_ecdh_pub;
    u32 peer_ecdh_pub_len;

    u8 *self_ecdh_pub;
    u8 *self_ecdh_prv;
    u32 self_ecdh_pub_len;
    u32 self_ecdh_prv_len;

    u8 pre_secret[A_CRYPTO_MAX_MD_LEN];
    u8 early_secret[A_CRYPTO_MAX_MD_LEN];
    u8 handshake_secret[A_CRYPTO_MAX_MD_LEN];
    u8 master_secret[A_CRYPTO_MAX_MD_LEN];
    u8 clnt_random[A_TLS_RAND_SIZE];
    u8 srv_random[A_TLS_RAND_SIZE];
    u8 finishkey[2][EVP_MAX_KEY_LENGTH];
    u8 handshake_secret_hash[A_CRYPTO_MAX_MD_LEN];
    u8 resumption_master_secret[A_CRYPTO_MAX_MD_LEN];
    u8 clnt_sig[A_TLS_MAX_SIG_ALG];
    u8 clnt_curve[A_TLS_MAX_GROUP];
    u16 ecdh_id;
    a_group_t *group;
    u8 state;
    u16 clnt_version;
    u16 version;
    u8 session_id[A_TLS_SESS_ID_SIZE];
    u8 *diget_cache;
    u32 diget_len;
    u32 diget_off;
    u32 sig_index;
    u8 *sni;
    u32 sni_len;
}a_tls_handshake_t;

typedef struct {

    /*OpenSSL object*/
    X509        *sign_cert;
    EVP_PKEY    *sign_key;
    X509        *cert[A_CRYPTO_NID_MAX];
    EVP_PKEY    *pkey[A_CRYPTO_NID_MAX];
    u32         curve;
    u32         gm_support;
    /*Formated text used by Handshake*/
    u8 *chain[A_CRYPTO_NID_MAX];
    u32 chain_len[A_CRYPTO_NID_MAX];

    u8 *der[A_CRYPTO_NID_MAX][10];
    u32 der_len[A_CRYPTO_NID_MAX][10];

    u8 *sign_der;
    u32 sign_der_len;

    u32 ticket;
    s32 (*early_data_cb)(void *tls, u8 *data, u32 data_len);
    u32 max_early_data;
    a_cipher_t  *cipers;
    u32 srv_prefer;
}a_tls_cfg_t;

typedef struct {
    s8 *name;
    u32 tls_id;
    u32 pkey;
    u32 md_nid;
    u32 curve;/*TLS1.3's curve*/
    u32 new;
    u32 mode;
    crypto_proc sign;
}sigalg_pair_t;

typedef struct {
    a_cipher_t *cipher;
    a_md_t *md;
    /*psk or master_secret*/
    u8 master_secret[A_TLS_MASTER_KEY_LEN];
    u8 *sni;
    u32 sni_len;
}a_tls_sess_t;

typedef struct {
    u8  *data;
    u32 len;
    u32 rt_type;
}msg_t;

struct a_tls;
typedef struct a_tls a_tls_t;

typedef struct {
    s32 (*enc)(a_tls_t *tls, crypto_info_t *info);
    s32 (*dec)(a_tls_t *tls, crypto_info_t *info);
    s32 (*init_cipher)(a_tls_t *tls, u32 flag);
    s32 (*change_cipher)(a_tls_t *tls, u32 flag);
    u32 flag;
} method_t;

typedef struct a_tls_err_s {
    struct a_tls_err_s *next;
    u32 str_len;
    s8 str[0];
} a_tls_err_t;

typedef s32 (*state_func)(a_tls_t *);
typedef s32 (*ext_func)(a_tls_t *, u8 *, u32);

struct a_tls {
    a_tls_cfg_t         *cfg;
    a_tls_sess_t        *sess;
    a_tls_handshake_t   *handshake;
    a_tls_buf_t         *nbio;
    a_tls_buf_t         *early_data;
    a_tls_buf_t         *saved_app;
    state_func          *state_proc;
    method_t            *spec;
    void                *write_ctx;
    void                *read_ctx;
    a_group_t           *group;
    sigalg_pair_t       *sig;
    a_group_t           *support_gp;
    a_tls_err_t         *err_stack;
    a_tls_err_t         *last_err;

    u8 *buf;/*used to save fragment data*/
    s32 fd;
    u32 flag;
    s8 err;
    s8 dir;
    u8 state;
    s8 read_state;
    s8 hit;
    u8 gm_support;
    u8 selected_cert;
    u16 version;
    u16 handshake_version;
    u8 mac_key[2][A_CRYPTO_MAX_MD_LEN];
    u8 key[2][A_CRYPTO_MAX_KEY_LEN];
    u8 iv[2][A_CRYPTO_MAX_IV_LEN];
    u8 seq[2][8];
    u8 cache[A_TLS_HEAD_LEN];
    u32 cache_len;
    u32 body_len;
    u32 body_read;
    u8 app_cache[A_TLS_HEAD_LEN];
    u8 app_cache_len;
    u16 nbio_plain;
    u8 nbio_state;
    struct {
        u8 psk_idx;
        u8 early_data;
        u8 sess_tikcet:1;
        u8 bind:1;
        u8 no_ext:1;
    } ext;
};


typedef struct {
    ext_func parse;
    ext_func gen;
    u32 next;
    u32 flag;
} ext_func_t;

/*tls.c*/
s32 a_tls_get_clnt_hello(a_tls_t *tls);
extern method_t tls_spec;
extern state_func tls_state_proc[];

/*lib.c*/
a_tls_buf_t *a_tls_buf_new(unsigned long size);
void a_tls_buf_free(a_tls_buf_t *ret);
s32 a_tls_nbio_flush(a_tls_t *tls);
s32 a_tls_get_hs_digest(a_tls_t *tls, u8 *out, u32 *out_len);
s32 a_tls_get_hs_data(a_tls_t *tls, u8 **out, u32 *out_len);
s32 a_tls_save_hs(a_tls_t *tls, u8 *data, s32 data_len);
s32 a_tls_snd_msg(a_tls_t *tls, u8 *data, s32 data_len, u8 type);
s32 a_tls_get_message(a_tls_t *tls, msg_t *msg, s32 type);
s32 a_tls_init(a_tls_t *tls);
s32 a_tls_do_write(a_tls_t *tls, u8 *data, s32 data_len, s32 *written);
s32 a_tls_check_version(a_tls_t *tls, u16 version);
s32 a_tls_get_sigalg_index(u32 nid);
s32 a_tls_process_cke_rsa(void *arg, u8 *in, u32 in_len);
s32 a_tls_process_cke_ecdh(void *arg, u8 *in, u32 in_len);
s32 a_tls_process_cke_ecc(void *arg, u8 *in, u32 in_len);
void a_tls_prf(a_tls_t *tls, u8 *buf,  u32 buf_len, u8 *sec, u32 sec_len, u8 *out1, u8 *out2, u32 olen);
s32 a_tls_gen_tls_hmac(a_md_t *md, u8 *key, u8 *add, u32 add_len, u8 *data, u32 data_len, u8 *out);
s32 a_tls_change_cipher(a_tls_t *tls, u32 flag);
void a_tls_free_tls(a_tls_t *tls);
void a_tls_free_sess(a_tls_sess_t *sess);
void *a_tls_malloc(unsigned long size);
void a_tls_free(void *p);
void *a_tls_new(a_tls_cfg_t *cfg);
void *a_tls_cfg_new();
void a_tls_cfg_free(a_tls_cfg_t *cfg);
void a_tls_cfg_check_cert(a_tls_cfg_t *cfg);

s32 a_tls_cfg_set_cert(a_tls_cfg_t *cfg, s8 *path);
s32 a_tls_cfg_set_sign_cert(a_tls_cfg_t *cfg, s8 *path);
s32 a_tls_cfg_set_sign_key(a_tls_cfg_t *cfg, s8 *path);
s32 a_tls_cfg_set_key(a_tls_cfg_t *cfg, s8 *path);
void a_tls_init_env();
void a_tls_set_fd(a_tls_t*, int);
s32 a_tls_handshake(a_tls_t *tls);
s32 a_tls_get_sni(a_tls_t *tls, s8 **data, u32 *len);
s32 a_tls_get_exchange_curve_name(a_tls_t *tls, s8 **data, u32 *len);
s32 a_tls_get_sign_curve_name(a_tls_t *tls, s8 **data, u32 *len);
s32 a_tls_get_cipher_name(a_tls_t *tls, s8 **data, u32 *len);
s32 a_tls_get_protocol_name(a_tls_t *tls, s8 **data, u32 *len);
s32 a_tls_get_handshake(a_tls_t *tls, s8 **data, u32 *len);
void a_tls_free_hs(a_tls_handshake_t *hs);

extern sigalg_pair_t g_sigalg_pair[];
extern u8 a_tls_tmp_record_buf[16384];
extern u8 a_tls_tmp_msg_buf[16384];
extern u8 a_tls_tmp_ciphertext_buf[16384];

s32 a_tls_process_clnt_hello(a_tls_t *tls, msg_t *msg);
s32 a_tls_construct_srv_hello(a_tls_t *tls,  u8 *buf);

/*kdf.c*/
s32 a_tls_hkdf_expand_label(a_md_t *md,
    u8 *secret, s8 *label, u8 *hash, u32 hash_len, u8 *out, u32 out_len);
s32 a_tls_derive_secret(a_md_t *md,
    u8 *secret, s8 *label, u8 *message, u32 message_len, u8 *out, u32 out_len);
void a_tls13_gen_master_secret(a_tls_t *tls);
void a_tls_gen_handshake_secret(a_tls_t *tls);
s32 a_tls_derive_key_and_iv(a_tls_t *tls, u32 flag);
s32 a_tls_derive_finished(a_md_t *md, u8 *secret, u8 *out, u32 out_len);

/*extension.c*/
s32 a_tls_parse_session_ticket(a_tls_t *tls, u8 *ticket, u32 ticket_len, a_tls_sess_t **sess);
s32 a_tls_gen_session_ticket(a_tls_t *tls, u8 *out, u32 *out_len);
s32 a_tls_construct_extension(a_tls_t *tls, u8 *buf, u32 type);
s32 a_tls_parse_extension(a_tls_t *tls, u8 *ext, s16 ext_len);
sigalg_pair_t * a_tls_select_sigalg(a_tls_t *tls, void **key, a_md_t **md);

/*tls13.c*/
extern state_func tls13_state_proc[A_TLS_STATE_MAX];
extern method_t tls13_spec;

/*tls_cipher.c*/
s32 a_tls13_dec_gcm_openssl(void *arg, crypto_info_t *info);
s32 a_tls13_enc_gcm_openssl(void *arg, crypto_info_t *info);
s32 a_tls13_init_cipher(a_tls_t *tls, u32 flag);
s32 a_tls_enc_cbc_openssl(void *arg, crypto_info_t *info);
s32 a_tls_dec_cbc_openssl(void *arg, crypto_info_t *info);
s32 a_tls_enc_gcm_openssl(void *arg, crypto_info_t *info);
s32 a_tls_dec_gcm_openssl(void *arg, crypto_info_t *info);
s32 a_tls_init_cipher(a_tls_t *tls, u32 flag);
s32 a_tls_read(a_tls_t *tls, u8 *buf, u32 len);
s32 a_tls_write(a_tls_t *tls, u8 *buf, u32 len);



typedef struct {
    unsigned long size;
} am_head_t;
#endif
