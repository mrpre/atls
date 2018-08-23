#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <a_crypto.h>
#include <a_tls.h>

unsigned char buf[1024];
unsigned short port = 44444;
#define replay "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 23\r\nServer: mrpre\r\n\r\nWelcome to mrpre's Home"
/*Simple A_TLS server*/
int main(int argc, char **argv)
{
    struct sockaddr_in server_addr;
    int listen_fd, opt;
    a_tls_cfg_t *cfg;
    a_tls_t *tls;
    struct timeval timeout={3,0};//3s

    a_tls_init_env();
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htons(INADDR_ANY);
    server_addr.sin_port = htons(port);

    listen_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("create socket error");
        exit(-1);
    }

    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    printf("Bind local port:%d\n", port);
    if( bind(listen_fd, (struct sockaddr*)&server_addr,sizeof(server_addr))) {
        perror("bind socket error");
        exit(-2);
    }

    if( listen(listen_fd, 256) ) {
        perror("listen socket error");
        exit(-2);
    }

    cfg = a_tls_cfg_new();
    if (cfg == NULL) {
        printf("a_tls_cfg_new error\n");
        exit(-2);
    }
#if 0
    printf("Setting ECC certificate\n");
    if (!a_tls_cfg_set_key(cfg, "./cert/ecc.key")) {
        printf("a_tls_cfg_set_key ecc.key error\n");
        exit(-2);
    }

    if (!a_tls_cfg_set_cert(cfg, "./cert/ecc.pem")) {
        printf("a_tls_cfg_set_cert ecc.pem error\n");
        exit(-2);
    }

    printf("Setting RSA certificate\n");
    if (!a_tls_cfg_set_key(cfg, "./cert/rsa.key")) {
       printf("a_tls_cfg_set_key rsa.key error\n");
       exit(-2);
    }

    if (!a_tls_cfg_set_cert(cfg, "./cert/rsa.pem")) {
        printf("a_tls_cfg_set_cert rsa.pem error\n");
        exit(-2);
    }
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    printf("Setting SM2 certificate\n");
    /*Now Setting ENC param*/
    if (!a_tls_cfg_set_key(cfg, "./cert/sm2.key")) {
       printf("a_tls_cfg_set_key sm2.key error\n");
       exit(-2);
    }

    if (!a_tls_cfg_set_cert(cfg, "./cert/sm2.pem")) {
        printf("a_tls_cfg_set_cert sm2.pem error\n");
        exit(-2);
    }

    /*Now Setting SIGN param*/
    if (!a_tls_cfg_set_sign_key(cfg, "./cert/sm2.key")) {
       printf("a_tls_cfg_set_key sm2.key error\n");
       exit(-2);
    }

    if (!a_tls_cfg_set_sign_cert(cfg, "./cert/sm2.pem")) {
        printf("a_tls_cfg_set_cert sm2.pem error\n");
        exit(-2);
    }
#else
    printf("Warning: GM SSL is not supported\n");
#endif

    for (;;) {
        struct sockaddr_in client_addr;
        int client_fd, ret;
        socklen_t length = sizeof(client_addr);

        printf("Waiting client's connection....\n");
        client_fd = accept(listen_fd,(struct sockaddr*)&client_addr,&length);
        if (client_fd < 0) {
            close(listen_fd);
            printf("accept error\n");
            exit(-2);
        }
        printf("process New client\n");
        tls = a_tls_new(cfg);
        if (tls == NULL) {
            close(listen_fd);
            printf("a_tls_new error\n");
            exit(-2);
        }

        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        a_tls_set_fd(tls, client_fd);
        if (a_tls_handshake(tls) != 0) {
            printf("a_tls_handshake error\n");
            goto next;
        }
        memset(buf, 0 ,sizeof(buf));
        printf("Try to read %zu bytes from client.....\n", sizeof(buf));
        ret = a_tls_read(tls ,buf, sizeof(buf));
        if (ret <= 0) {
            printf("ret:%d\n",ret);
            if (ret == A_TLS_READ_FIN) {
                printf("a_tls_read fin\n");
            } else {
                printf("a_tls_read error\n");
            }
            goto next;
        }
        printf("Recv %d bytes from client %s\n", ret, buf);
        ret = a_tls_write(tls, (unsigned char*)replay, sizeof(replay) - 1);
        printf("reply to client :%d\n",ret);
next:
        close(client_fd);
        a_tls_free_tls(tls);
    }
    a_tls_cfg_free(cfg);
    if (listen_fd) {
        close(listen_fd);
    }

    return 0;
}
