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

#define BORINGSSL_CIPHERS            \
    "TLS_AES_128_GCM_SHA256:"        \
    "TLS_CHACHA20_POLY1305_SHA256:"  \
    "TLS_AES_256_GCM_SHA384:"        \
    "ECDHE-ECDSA-AES128-GCM-SHA256:" \
    "ECDHE-RSA-AES128-GCM-SHA256:"   \
    "ECDHE-ECDSA-CHACHA20-POLY1305:" \
    "ECDHE-RSA-CHACHA20-POLY1305:"   \
    "ECDHE-ECDSA-AES256-GCM-SHA384:" \
    "ECDHE-RSA-AES256-GCM-SHA384:"   \
    "ECDHE-ECDSA-AES256-SHA:"        \
    "ECDHE-ECDSA-AES128-SHA:"        \
    "ECDHE-RSA-AES128-SHA:"          \
    "ECDHE-RSA-AES256-SHA:"          \
    "AES128-GCM-SHA256:"             \
    "AES256-GCM-SHA384:"             \
    "AES128-SHA:"                    \
    "AES256-SHA"

static int ZlibCompress(SSL *, CBB *out, const uint8_t *in, size_t in_len)
{
    uLongf max_len = compressBound(in_len);
    uint8_t *buf;
    if (!CBB_add_space(out, &buf, max_len))
        return 0;
    if (compress2(buf, &max_len, in, in_len, Z_BEST_COMPRESSION) != Z_OK)
        return 0;
    CBB_did_write(out, max_len);
    return 1;
}

static int ZlibDecompress(SSL *, CRYPTO_BUFFER **out,
                          size_t uncompressed_len,
                          const uint8_t *in, size_t in_len)
{
    uint8_t *buf = (uint8_t *)OPENSSL_malloc(uncompressed_len);
    if (!buf)
        return 0;
    uLongf len = uncompressed_len;
    if (uncompress(buf, &len, in, in_len) != Z_OK)
    {
        OPENSSL_free(buf);
        return 0;
    }
    *out = CRYPTO_BUFFER_new(buf, len, NULL);
    OPENSSL_free(buf);
    return *out != NULL;
}

static int BrotliCompress(SSL *, CBB *out,
                          const uint8_t *in, size_t in_len)
{
    size_t max_len = BrotliEncoderMaxCompressedSize(in_len);
    uint8_t *buf;
    if (!CBB_add_space(out, &buf, max_len))
        return 0;
    if (!BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY,
                               BROTLI_DEFAULT_WINDOW,
                               BROTLI_MODE_GENERIC,
                               in_len, in,
                               &max_len, buf))
        return 0;
    CBB_did_write(out, max_len);
    return 1;
}

static int BrotliDecompress(SSL *, CRYPTO_BUFFER **out,
                            size_t uncompressed_len,
                            const uint8_t *in, size_t in_len)
{
    uint8_t *buf = (uint8_t *)OPENSSL_malloc(uncompressed_len);
    if (!buf)
        return 0;
    size_t len = uncompressed_len;
    if (BrotliDecoderDecompress(in_len, in, &len, buf) != BROTLI_DECODER_RESULT_SUCCESS)
    {
        OPENSSL_free(buf);
        return 0;
    }
    *out = CRYPTO_BUFFER_new(buf, len, NULL);
    OPENSSL_free(buf);
    return *out != NULL;
}

static int ZstdCompress(SSL *, CBB *out,
                        const uint8_t *in, size_t in_len)
{
    size_t max_len = ZSTD_compressBound(in_len);
    uint8_t *buf;
    if (!CBB_add_space(out, &buf, max_len))
        return 0;
    size_t ret = ZSTD_compress(buf, max_len, in, in_len, 3);
    if (ZSTD_isError(ret))
        return 0;
    CBB_did_write(out, ret);
    return 1;
}

static int ZstdDecompress(SSL *, CRYPTO_BUFFER **out,
                          size_t uncompressed_len,
                          const uint8_t *in, size_t in_len)
{
    uint8_t *buf = (uint8_t *)OPENSSL_malloc(uncompressed_len);
    if (!buf)
        return 0;
    size_t ret = ZSTD_decompress(buf, uncompressed_len, in, in_len);
    if (ZSTD_isError(ret))
    {
        OPENSSL_free(buf);
        return 0;
    }
    *out = CRYPTO_BUFFER_new(buf, ret, NULL);
    OPENSSL_free(buf);
    return *out != NULL;
}

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
        "ECDSA+SHA512:"
        "RSA-PSS+SHA256:"
        "RSA-PSS+SHA384:"
        "RSA-PSS+SHA512:"
        "RSA+SHA256:"
        "RSA+SHA384:"
        "RSA+SHA512:"
        "ECDSA+SHA1:"
        "RSA+SHA1";

    const uint8_t alpn[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    SSL_CTX_add_cert_compression_alg(ctx, TLSEXT_cert_compression_zlib,
                                     ZlibCompress, ZlibDecompress);
    SSL_CTX_add_cert_compression_alg(ctx, TLSEXT_cert_compression_brotli,
                                     BrotliCompress, BrotliDecompress);
    SSL_CTX_add_cert_compression_alg(ctx, TLSEXT_cert_compression_zstd,
                                     ZstdCompress, ZstdDecompress);

    SSL_CTX_set1_sigalgs_list(ctx, sigalgs);

    SSL_CTX_set_strict_cipher_list(ctx, BORINGSSL_CIPHERS);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    SSL_CTX_set_record_size_limit(ctx, 4096);

    SSL_CTX_set_delegated_credentials(ctx, "RSA+SHA1:ECDSA+SHA256:ecdsa_secp256r1_sha256");

    SSL_CTX_enable_signed_cert_timestamps(ctx);

    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, hostname);

    int sock = connect_tcp(hostname, port, AF_INET);
    BIO *bio = BIO_new_socket(sock, BIO_CLOSE);
    SSL_set_bio(ssl, bio, bio);

    SSL_set_alpn_protos(ssl, alpn, sizeof(alpn));

    SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);

    SSL_set_enable_ech_grease(ssl, 1);

    if (SSL_connect(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf("Connected\n");

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
