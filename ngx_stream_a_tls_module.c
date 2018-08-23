/*
 * Copyright (C) Jiayuan Chen
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include "ngx_stream_a_tls_module.h"
#define NGX_DEFAULT_ATLS_CIPHERS "all"

static ngx_int_t
ngx_stream_a_tls_get_handshake(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_stream_a_tls_get_sni(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_stream_a_tls_get_protocol(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_stream_a_tls_get_cipher(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_stream_a_tls_get_sign_alg(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_stream_a_tls_get_exchange_curve(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_stream_a_tls_add_variables(ngx_conf_t *cf);
static ngx_int_t
ngx_stream_a_tls_init(ngx_conf_t *cf);
static ngx_int_t
ngx_stream_a_tls_handler(ngx_stream_session_t *s);
static void *
ngx_stream_a_tls_create_conf(ngx_conf_t *cf);
static char *
ngx_stream_a_tls_merge_conf(ngx_conf_t *cf, void *parent, void *child);
ngx_int_t
ngx_a_tls_handshake(ngx_connection_t *c);
void
ngx_a_tls_handshake_handler(ngx_event_t *ev);
void ngx_cdecl
ngx_a_tls_error(ngx_stream_session_t *s);

static ngx_command_t  ngx_stream_a_tls_commands[] = {

    { ngx_string("a_tls_certificate"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_a_tls_conf_t, certificates),
      NULL },

    { ngx_string("a_tls_certificate_key"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_a_tls_conf_t, certificate_keys),
      NULL },

    { ngx_string("a_tls_sign_certificate"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_a_tls_conf_t, sign_certificate),
      NULL },

    { ngx_string("a_tls_sign_certificate_key"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_a_tls_conf_t, sign_certificate_key),
      NULL },
#if 0
    { ngx_string("a_tls_ciphers"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_a_tls_conf_t, ciphers),
      NULL },
#endif
};

static ngx_stream_module_t  ngx_stream_a_tls_module_ctx = {
    ngx_stream_a_tls_add_variables,          /* preconfiguration */
    ngx_stream_a_tls_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_a_tls_create_conf,            /* create server configuration */
    ngx_stream_a_tls_merge_conf,              /* merge server configuration */
};


ngx_module_t  ngx_stream_a_tls_module = {
    NGX_MODULE_V1,
    &ngx_stream_a_tls_module_ctx,            /* module context */
    ngx_stream_a_tls_commands,               /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_stream_variable_t  ngx_stream_a_tls_vars[] = {

    { ngx_string("a_tls_handshake"), NULL, ngx_stream_a_tls_get_handshake,
      0, 0, 0 },

    { ngx_string("a_tls_sni"), NULL, ngx_stream_a_tls_get_sni,
      0, 0, 0 },

    { ngx_string("a_tls_protocol"), NULL, ngx_stream_a_tls_get_protocol,
      0, 0, 0 },

    { ngx_string("a_tls_cipher"), NULL, ngx_stream_a_tls_get_cipher,
      0, 0, 0 },

    { ngx_string("a_tls_sign_alg"), NULL, ngx_stream_a_tls_get_sign_alg,
      0, 0, 0 },

    { ngx_string("a_tls_exchange_curve"), NULL, ngx_stream_a_tls_get_exchange_curve,
      0, 0, 0 },

    ngx_stream_null_variable
};

static ngx_int_t
ngx_stream_a_tls_add_variables(ngx_conf_t *cf)
{
    ngx_stream_variable_t  *var, *v;

    for (v = ngx_stream_a_tls_vars; v->name.len; v++) {
        var = ngx_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_stream_a_tls_get_sni(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    unsigned                len;
    char                    *str;
    ngx_a_tls_connection_t  *ntls;
    ngx_connection_t        *c = s->connection;

    ntls = c->a_tls;
    if (ntls == NULL) {
        return NGX_ERROR;
    }

    if (!ntls->handshaked) {
        return ngx_stream_a_tls_get_handshake(s, v, data);

    } else {

        if (!a_tls_get_sni(ntls->connection, &str, &len)) {
            return NGX_ERROR;
        }
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char*)str;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_a_tls_get_handshake(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    unsigned                len, i;
    u_char                  *str;
    u_char                  *fstr;
    ngx_a_tls_connection_t  *ntls;
    ngx_connection_t        *c = s->connection;

    ntls = c->a_tls;
    if (ntls == NULL
        || ntls->err) {
        return NGX_ERROR;
    }

    ntls->err = 1;

    if (!a_tls_get_handshake(ntls->connection, (char **)&str, &len)) {
        return NGX_ERROR;
    }

    fstr = ngx_palloc(s->connection->pool, len*2);
    if (fstr == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < len; i++) {
        ngx_snprintf(&fstr[i*2], 2, "%02Xi", str[i]);
    }

    v->len = len*2;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = fstr;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_a_tls_get_protocol(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    unsigned                len;
    char                    *str;
    ngx_a_tls_connection_t  *ntls;
    ngx_connection_t        *c = s->connection;

    ntls = c->a_tls;
    if (ntls == NULL) {
        return NGX_ERROR;
    }

    if (!ntls->handshaked) {
        return ngx_stream_a_tls_get_handshake(s, v, data);

    } else {

        if (!a_tls_get_protocol_name(ntls->connection, &str, &len)) {
            return NGX_ERROR;
        }
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char*)str;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_a_tls_get_cipher(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    unsigned                len;
    char                    *str;
    ngx_a_tls_connection_t  *ntls;
    ngx_connection_t        *c = s->connection;

    ntls = c->a_tls;
    if (ntls == NULL) {
        return NGX_ERROR;
    }

    if (!ntls->handshaked) {
        return ngx_stream_a_tls_get_handshake(s, v, data);

    } else {
        if (!a_tls_get_cipher_name(ntls->connection, &str, &len)) {
            return NGX_ERROR;
        }
    }
    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char*)str;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_a_tls_get_sign_alg(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    unsigned                len;
    char                    *str;
    ngx_a_tls_connection_t  *ntls;
    ngx_connection_t        *c = s->connection;

    ntls = c->a_tls;
    if (ntls == NULL) {
        return NGX_ERROR;
    }

    if (!ntls->handshaked) {
        return ngx_stream_a_tls_get_handshake(s, v, data);

    } else {

        if (!a_tls_get_sign_curve_name(ntls->connection, &str, &len)) {
            return NGX_ERROR;
        }
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char*)str;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_a_tls_get_exchange_curve(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    unsigned                len;
    char                    *str;
    ngx_a_tls_connection_t  *ntls;
    ngx_connection_t        *c = s->connection;

    ntls = c->a_tls;
    if (ntls == NULL) {
        return NGX_ERROR;
    }

    if (!ntls->handshaked) {
        return ngx_stream_a_tls_get_handshake(s, v, data);

    } else {
        if (!a_tls_get_exchange_curve_name(ntls->connection, &str, &len)) {
            return NGX_ERROR;
        }
    }
    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char*)str;

    return NGX_OK;
}

static void *
ngx_stream_a_tls_create_conf(ngx_conf_t *cf)
{
    ngx_stream_a_tls_conf_t  *scf;

    scf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_a_tls_conf_t));
    if (scf == NULL) {
        return NULL;
    }

    scf->certificates           = NGX_CONF_UNSET_PTR;
    scf->certificate_keys       = NGX_CONF_UNSET_PTR;
    scf->sign_certificate       = NGX_CONF_UNSET_PTR;
    scf->sign_certificate_key   = NGX_CONF_UNSET_PTR;

    return scf;
}

static char *
ngx_a_tls_certificate(ngx_conf_t *cf, ngx_stream_a_tls_conf_t *conf)
{
    ngx_uint_t i;
    ngx_str_t   *cert, *key;

    if (conf->certificates == NULL) {
        return "ATLS No certificate configured";
    }

    if (conf->certificate_keys == NULL
        || conf->certificate_keys->nelts < conf->certificates->nelts)
    {
        return "ATLS the number of key is not equal to cetificate";
    }

    /*parse the key first, so we can find the lowest certificate in chain by the key*/
    key = conf->certificate_keys->elts;
    for (i = 0; i < conf->certificate_keys->nelts; i++) {

        if (ngx_conf_full_name(cf->cycle, &key[i], 1) != NGX_OK) {
            return "get ATLS key file error";
        }

        if (!a_tls_cfg_set_key(conf->tls_cfg, (char*)key[i].data)) {
            return "set ATLS SSL key file error";
        }
    }

    cert = conf->certificates->elts;
    for (i = 0; i < conf->certificates->nelts; i++) {

        if (ngx_conf_full_name(cf->cycle, &cert[i], 1) != NGX_OK) {
            return "get ATLS cert file error";
        }

        if (!a_tls_cfg_set_cert(conf->tls_cfg, (char*)cert[i].data)) {
            return "set ATLS cert file error";
        }
    }

    if (conf->certificates && conf->sign_certificate_key) {

        key = conf->sign_certificate_key->elts;
        for (i = 0; i < conf->sign_certificate_key->nelts; i++) {

            if (ngx_conf_full_name(cf->cycle, &key[i], 1) != NGX_OK) {
                return "get ATLS sign key file error";
            }

            if (!a_tls_cfg_set_sign_key(conf->tls_cfg, (char*)key[i].data)) {
                return "set ATLS sign key file error";
            }
        }

        cert = conf->sign_certificate->elts;
        for (i = 0; i < conf->sign_certificate->nelts; i++) {

            if (ngx_conf_full_name(cf->cycle, &cert[i], 1) != NGX_OK) {
                return "get ATLS sign cert file error";
            }

            if (!a_tls_cfg_set_sign_cert(conf->tls_cfg, (char*)cert[i].data)) {
                return "set ATLS sign cert file error";
            }
        }
    }
    return NGX_CONF_OK;
}


void
ngx_a_tls_cleanup_cfg(void *data)
{
    a_tls_cfg_free(data);
}

static char *
ngx_stream_a_tls_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    char                        *ret;
    ngx_pool_cleanup_t          *cln;
    ngx_stream_a_tls_conf_t     *prev = parent;
    ngx_stream_a_tls_conf_t     *conf = child;

    if (conf->certificates == NGX_CONF_UNSET_PTR
        && conf->certificate_keys == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_OK;
    }

    ngx_conf_merge_ptr_value(conf->certificates, prev->certificates, NULL);
    ngx_conf_merge_ptr_value(conf->certificate_keys, prev->certificate_keys,
                         NULL);
    ngx_conf_merge_ptr_value(conf->sign_certificate, prev->sign_certificate, NULL);

    ngx_conf_merge_ptr_value(conf->sign_certificate_key, prev->sign_certificate_key,
                         NULL);

    ngx_conf_merge_str_value(conf->ciphers, prev->ciphers, NGX_DEFAULT_ATLS_CIPHERS);

    conf->tls_cfg = a_tls_cfg_new();
    if (conf->tls_cfg == NULL) {
        return NGX_CONF_ERROR;
    }

    ret = ngx_a_tls_certificate(cf, conf);
    if (ret != NGX_CONF_OK) {
        return ret;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }
    cln->handler = ngx_a_tls_cleanup_cfg;
    cln->data = conf->tls_cfg;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_a_tls_init(ngx_conf_t *cf)
{
    ngx_stream_handler_pt        *h;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_SSL_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    a_tls_init_crypto_env();

    *h = ngx_stream_a_tls_handler;
    return NGX_OK;
}

static ngx_buf_t *
ngx_a_tls_get_buffer(ngx_a_tls_connection_t *ntls)
{
    return ntls->buf;
}

static ngx_int_t
ngx_a_tls_buffered(ngx_a_tls_connection_t *ntls)
{
    return ntls->buffered;
}


ssize_t
ngx_a_tls_write(ngx_connection_t *c, u_char *data, size_t size)
{
    int        n;
    ngx_a_tls_connection_t  *ntls;

    ntls = c->a_tls;

    n = a_tls_write(ntls->connection, data, size);
    if (n > 0) {
        c->sent += n;
        return n;
    }
    else if (n == -2) {
        c->write->ready = 0;
        return NGX_AGAIN;
    }

    return NGX_ERROR;
}


ngx_chain_t *
ngx_a_tls_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    int          n;
    ngx_uint_t   flush;
    ssize_t      send, size;
    ngx_buf_t   *buf;

    if (!ngx_a_tls_buffered(c->a_tls)) {

        while (in) {
            if (ngx_buf_special(in->buf)) {
                in = in->next;
                continue;
            }

            n = ngx_a_tls_write(c, in->buf->pos, in->buf->last - in->buf->pos);

            if (n == NGX_ERROR) {
                return NGX_CHAIN_ERROR;
            }

            if (n == NGX_AGAIN) {
                return in;
            }

            in->buf->pos += n;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        return in;
    }


    /* the maximum limit size is the maximum int32_t value - the page size */

    if (limit == 0 || limit > (off_t) (NGX_MAX_INT32_VALUE - ngx_pagesize)) {
        limit = NGX_MAX_INT32_VALUE - ngx_pagesize;
    }

    buf = ngx_a_tls_get_buffer(c->a_tls);

    send = buf->last - buf->pos;
    flush = (in == NULL) ? 1 : buf->flush;

    for ( ;; ) {

        while (in && buf->last < buf->end && send < limit) {
            if (in->buf->last_buf || in->buf->flush) {
                flush = 1;
            }

            if (ngx_buf_special(in->buf)) {
                in = in->next;
                continue;
            }

            size = in->buf->last - in->buf->pos;

            if (size > buf->end - buf->last) {
                size = buf->end - buf->last;
            }

            if (send + size > limit) {
                size = (ssize_t) (limit - send);
            }

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL buf copy: %z", size);

            ngx_memcpy(buf->last, in->buf->pos, size);

            buf->last += size;
            in->buf->pos += size;
            send += size;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        if (!flush && send < limit && buf->last < buf->end) {
            break;
        }

        size = buf->last - buf->pos;

        if (size == 0) {
            buf->flush = 0;
            c->buffered &= ~NGX_SSL_BUFFERED;
            return in;
        }

        n = ngx_a_tls_write(c, buf->pos, size);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (n == NGX_AGAIN) {
            break;
        }

        buf->pos += n;

        if (n < size) {
            break;
        }

        flush = 0;

        buf->pos = buf->start;
        buf->last = buf->start;

        if (in == NULL || send == limit) {
            break;
        }
    }

    buf->flush = flush;

    if (buf->pos < buf->last) {
        c->buffered |= NGX_SSL_BUFFERED;

    } else {
        c->buffered &= ~NGX_SSL_BUFFERED;
    }

    return in;
}



ssize_t
ngx_a_tls_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    int  n, total = 0;
    ngx_a_tls_connection_t  *ntls;

    ntls = c->a_tls;
again:
    n = a_tls_read(ntls->connection, buf, size);

    if (n > 0) {

        size  -= n;
        buf   += n;
        total += n;

        if (size) {
            goto again;
        }

        return total;
    }

    if (total) {
        c->read->ready = 1;
        return total;
    }

    if (n == -1) {
        c->read->ready = 0;
        return NGX_AGAIN;

    } else if (n == -6) {
        c->read->ready = 0;
        c->read->eof = 1;
        return 0;
    }
    c->read->error = 1;
    return NGX_ERROR;
}



ssize_t
ngx_a_tls_recv_chain(ngx_connection_t *c, ngx_chain_t *cl, off_t limit)
{
    u_char     *last;
    ssize_t     n, bytes, size;
    ngx_buf_t  *b;

    bytes = 0;

    b = cl->buf;
    last = b->last;

    for ( ;; ) {
        size = b->end - last;

        if (limit) {
            if (bytes >= limit) {
                return bytes;
            }

            if (bytes + size > limit) {
                size = (ssize_t) (limit - bytes);
            }
        }

        n = ngx_a_tls_recv(c, last, size);

        if (n > 0) {
            last += n;
            bytes += n;

            if (last == b->end) {
                cl = cl->next;

                if (cl == NULL) {
                    return bytes;
                }

                b = cl->buf;
                last = b->last;
            }

            continue;
        }

        if (bytes) {

            if (n == 0 || n == NGX_ERROR) {
                c->read->ready = 1;
            }

            return bytes;
        }

        return n;
    }
}

void a_tls_free_ntls(void *data)
{
    a_tls_free_tls(data);
}

ngx_int_t
ngx_a_tls_handshake(ngx_connection_t *c)
{
    ngx_int_t rc;
    ngx_a_tls_connection_t  *ntls;

    ntls = c->a_tls;

    rc = a_tls_handshake(ntls->connection);
    ngx_log_error(NGX_LOG_ERR, c->log, 0, "c:%p s:%p a_tls_handshake ret:%d", c, c->data, rc);

    if (rc == -1) {
        c->read->handler = ngx_a_tls_handshake_handler;
        c->write->handler = ngx_a_tls_handshake_handler;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "in ngx_a_tls_handshake read_event");
            return NGX_ERROR;
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "in ngx_a_tls_handshake write_event");
            return NGX_ERROR;
        }
        return NGX_AGAIN;
    }

    if (rc == -2) {
        c->read->handler = ngx_a_tls_handshake_handler;
        c->write->handler = ngx_a_tls_handshake_handler;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "in ngx_a_tls_handshake read_event");
            return NGX_ERROR;
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "in ngx_a_tls_handshake write_event");
            return NGX_ERROR;
        }
        return NGX_AGAIN;
    }

    if (rc == -3) {
        ngx_a_tls_error(c->data);
        //ngx_log_error(NGX_LOG_ERR, c->log, 0, "a_tls timed out");
        return NGX_ERROR;
    }

    if (rc == -6) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "peer close");
        return NGX_ERROR;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    ntls->handshaked = 1;

    c->recv = ngx_a_tls_recv;
    c->send = ngx_a_tls_write;
    c->recv_chain = ngx_a_tls_recv_chain;
    c->send_chain = ngx_a_tls_send_chain;

    return NGX_OK;
}


void
ngx_a_tls_handshake_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;
    ngx_a_tls_connection_t *ntls;

    c = ev->data;

    ntls = c->a_tls;

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "a_tls handshake timed out");

        ngx_stream_finalize_session(c->data, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_a_tls_handshake(c) == NGX_AGAIN) {
        return;
    }

    ntls->handler(c);
}


static void
ngx_stream_a_tls_handshake_handler(ngx_connection_t *c)
{
    ngx_stream_session_t  *s;
    ngx_a_tls_connection_t  *ntls;

    s = c->data;
    ntls = c->a_tls;

    if (!ntls->handshaked) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "not handshaked ");
        ngx_stream_finalize_session(c->data, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    ngx_stream_core_run_phases(s);
}

static ngx_int_t
ngx_stream_a_tls_create_connection(ngx_connection_t *c)
{
    ngx_a_tls_connection_t  *ntls;
    ngx_stream_a_tls_conf_t *tlscf;
    ngx_pool_cleanup_t      *cln;
    ngx_stream_session_t    *s = c->data;

    tlscf = ngx_stream_get_module_srv_conf(s, ngx_stream_a_tls_module);

    ntls = ngx_pcalloc(c->pool, sizeof(ngx_a_tls_connection_t));
    if (ntls == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_a_tls_connection_t alloc error");
        return NGX_ERROR;
    }

    ntls->buf = ngx_create_temp_buf(c->pool, 1440);
    if (ntls->buf == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "sc buf alloc error");
        return NGX_ERROR;
    }

    ntls->connection = a_tls_new(tlscf->tls_cfg);
    if (ntls->connection == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "a_tls_new error");
        return NGX_ERROR;
    }

    ntls->buffered = 0;

    a_tls_set_fd(ntls->connection, c->fd);

    c->a_tls = ntls;

    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "cleanup new error");
        return NGX_ERROR;
    }

    cln->data = ntls->connection;
    cln->handler = a_tls_free_ntls;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_a_tls_handler(ngx_stream_session_t *s)
{
    ngx_int_t rc;
    ngx_a_tls_connection_t *ntls;
    ngx_connection_t *c = s->connection;
    ngx_stream_a_tls_conf_t *tlscf;

    tlscf = ngx_stream_get_module_srv_conf(s, ngx_stream_a_tls_module);

    /*not configured, usging next ssl phase*/
    if (tlscf->certificates == NGX_CONF_UNSET_PTR
        || tlscf->certificate_keys == NGX_CONF_UNSET_PTR) {
        return NGX_DECLINED;
    }

    if (c->a_tls) {
        return NGX_OK;
    }

    if (ngx_stream_a_tls_create_connection(c) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_stream_a_tls_create_connection error");
        return NGX_ERROR;
    }

    rc = ngx_a_tls_handshake(c);
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_a_tls_handshake error");
        return NGX_ERROR;
    }

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->read, 10000);

        ntls = c->a_tls;
        ntls->handler = ngx_stream_a_tls_handshake_handler;

        return NGX_AGAIN;
    }

    return NGX_OK;
}

void ngx_cdecl
ngx_a_tls_error(ngx_stream_session_t *s)
{
    ngx_a_tls_connection_t *ntls;
    ngx_connection_t *c;

    u_long       n;
    u_char      *p, *last;
    u_char       errstr[NGX_MAX_CONF_ERRSTR];
    char        *data;

    c = s->connection;
    ntls = c->a_tls;

    last = errstr + NGX_MAX_CONF_ERRSTR;
    p    = errstr;

    p = ngx_cpystrn(p, (u_char *) "A_TLS err: \n", last - p);

    for ( ;; ) {

        if (p >= last - 1) {
            break;
        }

        n = a_tls_pop_err(ntls->connection, &data);

        if (n == 0) {
            break;
        }

        p = ngx_cpystrn(p, (u_char *) data, last - p - 1);
        *p++ = '\n';
    }

    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, (const char*)errstr);

}

