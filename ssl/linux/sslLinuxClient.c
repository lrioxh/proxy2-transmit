#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

int main() {
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());

    if (!ctx) {
        perror("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    SSL *ssl;
    BIO *bio;

    bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    BIO_set_conn_hostname(bio, "localhost:4433"); // Change to your server's address and port

    if (BIO_do_connect(bio) <= 0) {
        perror("Error connecting");
        exit(EXIT_FAILURE);
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        perror("Certificate verification error");
        exit(EXIT_FAILURE);
    }

    BIO_puts(bio, "Hello, Server!\n");

    char buffer[1024];
    BIO_read(bio, buffer, sizeof(buffer));
    printf("Server response: %s\n", buffer);

    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    return 0;
}