# Atls  
A lite TLS implementation used for learning(TLS 1.0 TLS 1.1 TLS 1.2 TLS 1.3 GMSSL 1.1 ) based on libcrypto.so.
  
1.Not supporting multiplethreading.  
2.The memory used for Atls(handshaked session) is less than 1k + 2*EVP_CIPHER_CTX(OpenSSL).  

## For daemon using  
`make`  
`./daemon_server`  
  
You can also specify the newer libcrypto.so by using `cryptodir` where the OpenSSL being compiled and installed to.  
`make cryptodir=/$YOURPATH/openssl/.openssl`
  
For GMSSL or X25519, the version of libcrypto.so must be greater than 1.1.0.
  
## For Nginx using(Version 1.13.12)  
Add `void *a_tls;` into `struct ngx_connection_s`.    
compile like```./configure --add-module=/$YOURPATH/a_tls/ --with-stream --with-http_ssl_module --with-stream_ssl_module```.

### Common Directives
```
stream {
    ....
    server {
        ....
        a_tls_certificate ecc.pem;
        a_tls_certificate_key ecc.key;
        a_tls_certificate rsa.pem;
        a_tls_certificate_key rsa.key;
    }
}
```
### GMSSL Directives
```
stream {
    ....
    server {
        ....
        a_tls_certificate gm.cert;
        a_tls_certificate_key gm.key;
        a_tls_sign_certificate gm.cert;
        a_tls_sign_certificate_key gm.key;
    }
}
```
You can also mix SM2 certificate and TLS certificate to support both TLS and GMSSL.

## Tips  
For using GMSSL, plz using 360 GM browser and then change your client's local time before 01/01/2018(caues the daemon certificate has expired).  

## BUG reporting  
1: Using Wireshark to capture the TLS packet.  
2: Using `make DEBUG=1` and paste the log info.  
3: Certificates and Keys(Option).  
4: Nginx configure file(Option).  
5: Send to `mrpre@163.com`.  
