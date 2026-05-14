#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define LISTEN_PORT 443
#define BACKEND_HOST "127.0.0.1"
#define BACKEND_PORT "10000"

struct conn_t
{
    int client_fd;
};

int connect_backend()
{
    struct addrinfo hints, *res, *rp;
    int sock = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(BACKEND_HOST, BACKEND_PORT, &hints, &res) != 0)
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

void *forward_tls_to_tcp(void *arg)
{
    auto *p = (std::pair<SSL *, int> *)arg;
    SSL *ssl = p->first;
    int backend = p->second;

    char buf[4096];
    int n;

    while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0)
    {
        if (write(backend, buf, n) <= 0)
            break;
    }

    shutdown(backend, SHUT_WR);
    return nullptr;
}

void *forward_tcp_to_tls(void *arg)
{
    auto *p = (std::pair<SSL *, int> *)arg;
    SSL *ssl = p->first;
    int backend = p->second;

    char buf[4096];
    int n;

    while ((n = read(backend, buf, sizeof(buf))) > 0)
    {
        if (SSL_write(ssl, buf, n) <= 0)
            break;
    }

    SSL_shutdown(ssl);
    return nullptr;
}

void *handle_conn(void *arg)
{
    conn_t *conn = (conn_t *)arg;
    int client_fd = conn->client_fd;

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        close(client_fd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        delete conn;
        return nullptr;
    }

    std::cout << "Client connected\n";

    int backend = connect_backend();
    if (backend < 0)
    {
        std::cerr << "Backend connection failed\n";
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(client_fd);
        delete conn;
        return nullptr;
    }

    pthread_t t1, t2;

    auto *p1 = new std::pair<SSL *, int>(ssl, backend);
    auto *p2 = new std::pair<SSL *, int>(ssl, backend);

    pthread_create(&t1, nullptr, forward_tls_to_tcp, p1);
    pthread_create(&t2, nullptr, forward_tcp_to_tls, p2);

    pthread_join(t1, nullptr);
    pthread_join(t2, nullptr);

    delete p1;
    delete p2;

    close(backend);
    close(client_fd);

    SSL_free(ssl);
    SSL_CTX_free(ctx);

    delete conn;
    return nullptr;
}

int main()
{
    SSL_library_init();

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

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

    std::cout << "Listening on port " << LISTEN_PORT << "\n";

    while (true)
    {
        sockaddr_in client_addr{};
        socklen_t len = sizeof(client_addr);

        int client_fd = accept(server_fd, (sockaddr *)&client_addr, &len);
        if (client_fd < 0)
            continue;

        conn_t *conn = new conn_t;
        conn->client_fd = client_fd;

        pthread_t tid;
        pthread_create(&tid, nullptr, handle_conn, conn);
        pthread_detach(tid);
    }

    return 0;
}