#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

int main() {
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());

    if (!ctx) {
        perror("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        perror("Error loading server certificate");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        perror("Error loading server private key");
        exit(EXIT_FAILURE);
    }

    SSL *ssl;
    BIO *bio, *accept_bio;

    bio = BIO_new_ssl(ctx, 0);
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    accept_bio = BIO_new_accept("4433"); // Port for incoming connections
    BIO_set_accept_bios(accept_bio, bio);

    if (BIO_do_accept(accept_bio) <= 0) {
        perror("Error accepting connection");
        exit(EXIT_FAILURE);
    }

    BIO *client = BIO_pop(accept_bio);

    char buffer[1024];
    BIO_read(client, buffer, sizeof(buffer));
    printf("Client message: %s\n", buffer);

    const char *response = "Hello, Client!\n";
    BIO_write(client, response, strlen(response));

    BIO_free_all(client);
    BIO_free_all(accept_bio);
    SSL_CTX_free(ctx);

    return 0;
}