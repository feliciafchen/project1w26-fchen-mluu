#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024
#define LOCAL_PORT_TO_CLIENT 8443
#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PORT 5001

void handle_request(SSL *ssl);
void send_local_file(SSL *ssl, const char *path);
void proxy_remote_file(SSL *ssl, const char *request);
int file_exists(const char *filename);

// TODO: Parse command-line arguments (-b/-r/-p) and override defaults.
// Keep behavior consistent with the project spec.
void parse_args(int argc, char *argv[], int *local_p, char **remote_h, int *remote_p)
{
    (void)argc;
    (void)argv;

    int opt;

    // All options are optional
    // -b -> local port
    // -r -> remote host
    // -p -> remote port

    while ((opt = getopt(argc, argv, "b:r:p:")) != -1)
    {
        switch (opt)
        {
        case 'b':
            *local_p = atoi(optarg);
            break;
        case 'r':
            *remote_h = optarg;
            break;
        case 'p':
            *remote_p = atoi(optarg);
            break;
        case '?':
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char *argv[])
{
    SSL_load_error_strings();
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    int local_port = 8443;
    char *remote_host = "127.0.0.1";
    int remote_port = 5001;

    parse_args(argc, argv, &local_port, &remote_host, &remote_port);

    // TODO: Initialize OpenSSL library
    OPENSSL_init_ssl(0, NULL);

    // TODO: Create SSL context and load certificate/private key files
    const SSL_METHOD *method = TLS_server_method();
    // Files: "server.crt" and "server.key"
    SSL_CTX *ssl_ctx = SSL_CTX_new(method);

    if (ssl_ctx == NULL)
    {
        fprintf(stderr, "Error: SSL context not initialized\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Error: failed to load certificate\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Error: failed to load private key\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_check_private_key(ssl_ctx) != 1)
    {
        fprintf(stderr, "Error: private key does not match certificate\n");
        exit(EXIT_FAILURE);
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(LOCAL_PORT_TO_CLIENT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    if (listen(server_socket, 10) == -1)
    {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Proxy server listening on port %d\n", LOCAL_PORT_TO_CLIENT);

    while (1)
    {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket == -1)
        {
            perror("accept failed");
            continue;
        }

        printf("Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // Create SSL structure for this connection and perform SSL handshake
        SSL *ssl = SSL_new(ssl_ctx);
        if (!ssl || SSL_set_fd(ssl, client_socket) != 1 || SSL_accept(ssl) != 1)
        {
            if (ssl)
                SSL_free(ssl);
            close(client_socket);
            continue;
        }

        handle_request(ssl);

        // Clean up SSL connection
        SSL_shutdown(ssl);
        SSL_free(ssl);

        close(client_socket);
    }

    close(server_socket);
    // TODO: Clean up SSL context
    SSL_CTX_free(ssl_ctx);
    ERR_print_errors_fp(stderr);
    return 0;
}

int file_exists(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file != NULL)
    {
        fclose(file);
        return 1;
    }
    return 0;
}

// TODO: Parse HTTP request, extract file path, and route to appropriate handler
// Consider: URL decoding, default files, routing logic for different file types
void handle_request(SSL *ssl)
{
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // TODO: Read request from SSL connection
    bytes_read = SSL_read(ssl, buffer, BUFFER_SIZE - 1);

    if (bytes_read <= 0)
    {
        return;
    }

    buffer[bytes_read] = '\0';
    char *request = malloc(strlen(buffer) + 1);
    strcpy(request, buffer);

    char *method = strtok(request, " ");
    char *file_name = strtok(NULL, " ");
    file_name++;
    if (strlen(file_name) == 0)
    {
        strcat(file_name, "index.html");
    }
    char *http_version = strtok(NULL, " ");

    if (file_exists(file_name))
    {
        printf("Sending local file %s\n", file_name);
        send_local_file(ssl, file_name);
    }
    else
    {
        printf("Proxying remote file %s\n", file_name);
        proxy_remote_file(ssl, buffer);
    }

    free(request);
}

// TODO: Serve local file with correct Content-Type header
// Support: .html, .txt, .jpg, .m3u8, and files without extension
void send_local_file(SSL *ssl, const char *path)
{
    FILE *file = fopen(path, "rb");
    char buffer[BUFFER_SIZE];
    size_t bytes_read;

    if (!file)
    {
        // File not found response (404)
        printf("File %s not found\n", path);
        char *response = "HTTP/1.1 404 Not Found\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                         "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
                         "<body><h1>404 Not Found</h1></body></html>";
        SSL_write(ssl, response, strlen(response));

        return;
    }

    char *response;
    if (strstr(path, ".html"))
    {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/html; charset=UTF-8\r\n\r\n";
    }
    else if (strstr(path, ".jpg"))
    {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: image/jpeg; charset=UTF-8\r\n\r\n";
    }
    else if (strstr(path, ".m3u8"))
    {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/x-mpegURL;\r\n\r\n";
    }
    else
    {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/plain;\r\n\r\n";
    }

    // TODO: Send response header and file content via SSL
    SSL_write(ssl, response, strlen(response));
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        // TODO: Send file data via SSL
        SSL_write(ssl, buffer, bytes_read);
    }

    fclose(file);
}

// TODO: Forward request to backend server and relay response to client
// Handle connection failures appropriately
void proxy_remote_file(SSL *ssl, const char *request)
{
    int remote_socket;
    struct sockaddr_in remote_addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_socket == -1)
    {
        printf("Failed to create remote socket\n");
        return;
    }

    remote_addr.sin_family = AF_INET;
    inet_pton(AF_INET, REMOTE_HOST, &remote_addr.sin_addr);
    remote_addr.sin_port = htons(REMOTE_PORT);

    if (connect(remote_socket, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) == -1)
    {
        printf("Failed to connect to remote server\n");
        close(remote_socket);
        return;
    }

    send(remote_socket, request, strlen(request), 0);

    while ((bytes_read = recv(remote_socket, buffer, sizeof(buffer), 0)) > 0)
    {
        // TODO: Forward response to client via SSL
        SSL_write(ssl, buffer, bytes_read);
    }

    close(remote_socket);
}
