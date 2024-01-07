#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

void handleErrors(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

void generate_keypair(EC_KEY **eckey) {
    *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!*eckey) {
        handleErrors("Error generating EC key");
    }

    if (!EC_KEY_generate_key(*eckey)) {
        handleErrors("Error generating EC key pair");
    }
}

void ec_encrypt(const char *plaintext, size_t plaintext_len, EC_KEY *public_key) {
    size_t ciphertext_len;
    unsigned char *ciphertext = NULL;

    ciphertext_len = ECIES_encrypt(public_key, (const unsigned char *)plaintext, plaintext_len, &ciphertext);
    if (ciphertext_len <= 0) {
        handleErrors("Error encrypting data");
    }

    printf("Encrypted Text: ");
    for (size_t i = 0; i < ciphertext_len; i++) {
        printf("%02X", ciphertext[i]);
    }
    printf("\n");

    OPENSSL_free(ciphertext);
}

void ec_decrypt(const unsigned char *ciphertext, size_t ciphertext_len, EC_KEY *private_key) {
    size_t decrypted_len;
    char *decrypted_text = NULL;

    decrypted_len = ECIES_decrypt(private_key, ciphertext, ciphertext_len, (unsigned char **)&decrypted_text);
    if (decrypted_len <= 0) {
        handleErrors("Error decrypting data");
    }

    printf("Decrypted Text: %s\n", decrypted_text);

    OPENSSL_free(decrypted_text);
}

int main() {
    EC_KEY *public_key = NULL;
    EC_KEY *private_key = NULL;

    generate_keypair(&public_key);
    generate_keypair(&private_key);

    const char *plaintext = "Hello, ECC!";
    size_t plaintext_len = strlen(plaintext);

    printf("Original Text: %s\n", plaintext);

    ec_encrypt(plaintext, plaintext_len, public_key);
    ec_decrypt(ciphertext, ciphertext_len, private_key);

    EC_KEY_free(public_key);
    EC_KEY_free(private_key);

    return 0;
}
