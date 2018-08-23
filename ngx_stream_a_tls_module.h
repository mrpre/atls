
/*
 * Copyright (C) Jiayuan Chen
 */


#ifndef _NGX_STREAM_A_TLS_H_INCLUDED_
#define _NGX_STREAM_A_TLS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


typedef struct {
    void            *tls_cfg;
    ngx_int_t       flag;
    ngx_array_t     *certificates;
    ngx_array_t     *certificate_keys;
    ngx_array_t     *sign_certificate;
    ngx_array_t     *sign_certificate_key;
    ngx_str_t       ciphers;
} ngx_stream_a_tls_conf_t;

typedef struct {
    ngx_int_t handshaked;
    void *connection;
    ngx_buf_t *buf;
    ngx_int_t buffered;
    ngx_int_t err;
    ngx_connection_handler_pt handler;
} ngx_a_tls_connection_t;

extern ngx_module_t  ngx_stream_a_tls_module;
extern int a_tls_handshake(void *);
extern void a_tls_set_fd(void *, signed);
extern void *a_tls_new(void *);
extern void a_tls_free_tls(void *);
extern int a_tls_cfg_set_cert(void *, char *);
extern int a_tls_cfg_set_sign_cert(void *, char *);
extern int a_tls_cfg_set_sign_key(void *, char *);
extern int a_tls_cfg_set_key(void *, char *);
extern void *a_tls_cfg_new();
extern void a_tls_cfg_free(void*);
extern int a_tls_read(void *, u_char *, unsigned);
extern int a_tls_write(void *, u_char *, unsigned);
extern int a_tls_get_exchange_curve_name(void *, char **, unsigned *);
extern int a_tls_get_sign_curve_name(void *, char **, unsigned *);
extern int a_tls_get_cipher_name(void *, char **, unsigned *);
extern int a_tls_get_protocol_name(void *, char **, unsigned *);
extern int a_tls_get_sni(void *, char **, unsigned *);
extern int a_tls_get_handshake(void *, char **, unsigned *);
extern void a_tls_init_crypto_env();
extern int a_tls_pop_err(void *, char **);

#endif /* _NGX_STREAM_A_TLS_H_INCLUDED_ */

