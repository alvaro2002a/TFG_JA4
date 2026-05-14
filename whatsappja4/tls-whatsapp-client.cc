#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <zlib.h>
#include <brotli/encode.h>
#include <brotli/decode.h>
#include <zstd.h>

#define BORINGSSL_CIPHERS \
    "TLS_AES_128_GCM_SHA256:"

static int connect_tcp(const char *hostname, const char *port, int family)
{
    struct addrinfo hints{}, *res = nullptr, *rp = nullptr;
    int sock = -1;
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, port, &hints, &res) != 0)
        return -1;

    for (rp = res; rp; rp = rp->ai_next)
    {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1)
            continue;
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}

int main()
{
    const char *hostname = "127.0.0.1";
    const char *port = "5050";

    const char *sigalgs =
        "ECDSA+SHA256:"
        "ECDSA+SHA384:"
        "RSA-PSS+SHA512:"
        "RSA-PSS+SHA384:"
        "RSA-PSS+SHA256:"
        "RSA+SHA512:"
        "RSA+SHA384:"
        "RSA+SHA256:";

    const uint8_t alpn[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    SSL_CTX_set1_sigalgs_list(ctx, sigalgs);

    SSL_CTX_set_cipher_list(ctx, BORINGSSL_CIPHERS);
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, hostname);

    int sock = connect_tcp(hostname, port, AF_INET);
    BIO *bio = BIO_new_socket(sock, BIO_CLOSE);
    SSL_set_bio(ssl, bio, bio);

    SSL_set_alpn_protos(ssl, alpn, sizeof(alpn));

    if (SSL_connect(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf("TLS connected\n");

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
