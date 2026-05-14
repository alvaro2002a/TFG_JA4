#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define LISTEN_PORT 5050
#define REMOTE_HOST "192.168.1.69"
#define SNI "z-m-gateway.facebook.com"
#define REMOTE_PORT "443"

#define BORINGSSL_CIPHERS \
    "TLS_AES_128_GCM_SHA256:"

struct conn_t
{
    int client_fd;
};

int connect_tcp(const char *host, const char *port)
{
    struct addrinfo hints, *res, *rp;
    int sock = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0)
    {
        perror("getaddrinfo");
        return -1;
    }

    for (rp = res; rp != nullptr; rp = rp->ai_next)
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

struct tls_pair
{
    int client_fd;
    SSL *ssl;
};

void *forward_client_to_tls(void *arg)
{
    tls_pair *p = (tls_pair *)arg;

    char buffer[4096];
    int n;

    while ((n = read(p->client_fd, buffer, sizeof(buffer))) > 0)
    {
        if (SSL_write(p->ssl, buffer, n) <= 0)
        {
            break;
        }
    }

    SSL_shutdown(p->ssl);
    return nullptr;
}

void *forward_tls_to_client(void *arg)
{
    tls_pair *p = (tls_pair *)arg;

    char buffer[4096];
    int n;

    while ((n = SSL_read(p->ssl, buffer, sizeof(buffer))) > 0)
    {
        if (write(p->client_fd, buffer, n) <= 0)
        {
            break;
        }
    }

    shutdown(p->client_fd, SHUT_WR);
    return nullptr;
}

void *handle_conn(void *arg)
{
    conn_t *conn = (conn_t *)arg;
    int client_fd = conn->client_fd;

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    SSL_CTX_set_cipher_list(ctx, BORINGSSL_CIPHERS);

    const char *sigalgs =
        "ECDSA+SHA256:"
        "ECDSA+SHA384:"
        "RSA-PSS+SHA512:"
        "RSA-PSS+SHA384:"
        "RSA-PSS+SHA256:"
        "RSA+SHA512:"
        "RSA+SHA384:"
        "RSA+SHA256:";

    SSL_CTX_set1_sigalgs_list(ctx, sigalgs);

    int sock = connect_tcp(REMOTE_HOST, REMOTE_PORT);
    if (sock < 0)
    {
        std::cerr << "Connection failed\n";
        close(client_fd);
        delete conn;
        return nullptr;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, SNI);

    const uint8_t alpn[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

    SSL_set_alpn_protos(ssl, alpn, sizeof(alpn));

    if (SSL_connect(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        close(client_fd);
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        delete conn;
        return nullptr;
    }

    std::cout << "Connected to " << REMOTE_HOST << "\n";

    pthread_t t1, t2;

    tls_pair *p1 = new tls_pair{client_fd, ssl};
    tls_pair *p2 = new tls_pair{client_fd, ssl};

    pthread_create(&t1, nullptr, forward_client_to_tls, p1);
    pthread_create(&t2, nullptr, forward_tls_to_client, p2);

    pthread_join(t1, nullptr);
    pthread_join(t2, nullptr);

    delete p1;
    delete p2;

    SSL_free(ssl);
    SSL_CTX_free(ctx);

    close(client_fd);
    close(sock);

    delete conn;
    return nullptr;
}

int main()
{
    SSL_library_init();

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("socket");
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(LISTEN_PORT);

    if (bind(server_fd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        return 1;
    }

    if (listen(server_fd, 10) < 0)
    {
        perror("listen");
        return 1;
    }

    std::cout << "Listening 127.0.0.1:" << LISTEN_PORT << "\n";

    while (true)
    {
        sockaddr_in client_addr{};
        socklen_t len = sizeof(client_addr);

        int client_fd = accept(server_fd, (sockaddr *)&client_addr, &len);
        if (client_fd < 0)
        {
            perror("accept");
            continue;
        }

        conn_t *conn = new conn_t;
        conn->client_fd = client_fd;

        pthread_t tid;
        pthread_create(&tid, nullptr, handle_conn, conn);
        pthread_detach(tid);
    }

    return 0;
}