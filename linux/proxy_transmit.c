// TODO
// clean code
// Abnormal treatment
//
// 1. Get and replace server cert(publicKey) o
// 2. get PMS from client, decrypt, encrypt again using proxy key, o
//    generate MS and SK
// 3. calculate MAC

//

// global var:filePaths; Randoms; X509* certs;
// to use struct

// sudo tcpdump -iany tcp port 4322
// sudo wireshark

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/unistd.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/ssl.h>
// #include <openssl/pem.h>
#include <openssl/kdf.h>
// #include <openssl/sha.h>
#include <openssl/aes.h>
// #include <openssl/x509.h>
// #include "include/s3cbc.h"

#define MAX_EVENTS (10) // epoll
#define MAX_RETRY (30)  // nonblock 30*2ms
#define BACKLOG (5)     // 最大监听数
#define BUFSIZE (65536)
#define PORT2SERV (4321)
#define PORT2CLNT (4322)
#define nonBlockMode (1)
#define C2S (1)
#define S2C (-1)
#define GET_2BYTE(buf) (((buf)[0] << 8) | (buf)[1])
#define GET_3BYTE(buf) (((buf)[0] << 16) | ((buf)[1] << 8) | (buf)[2])

const char *const pCAPath = "../ssl/ca/ca.crt";
const char *const certificate_path = "../ssl/ca/proxy.crt";
const char *const private_key_path = "../ssl/ca/proxy.key";

#define RSA_2048_SIZE 256
#define AES_BITS_LEN 128
#define TLS_HEAD_LEN 5
#define HS_HEAD_LEN 4
typedef unsigned char uint8_t;
typedef struct key_block_st
{
    uint8_t client_write_MAC_key[SHA256_DIGEST_LENGTH];
    uint8_t server_write_MAC_key[SHA256_DIGEST_LENGTH];
    uint8_t client_write_key[AES_BLOCK_SIZE];
    uint8_t server_write_key[AES_BLOCK_SIZE];
    // uint8_t client_write_IV[AES_BLOCK_SIZE];
    // uint8_t server_write_IV[AES_BLOCK_SIZE];
} KEY_block;

typedef struct proxy_states_st
{
    EVP_MD *md;
    X509 *cert_proxy;
    X509 *cert_server;
    KEY_block *key_block;
    // uint8_t *client_HS_buf;
    // uint8_t *server_HS_buf;
    // size_t client_HS_len;
    // size_t server_HS_len;
    uint8_t random_server[SSL3_RANDOM_SIZE];
    uint8_t random_client[SSL3_RANDOM_SIZE];
    uint8_t master_secret[SSL3_MASTER_SECRET_SIZE];

    // HMAC_CTX *mac_client;
    // HMAC_CTX *mac_server;
    // EVP_MD_CTX *mac_client;
    // EVP_MD_CTX *mac_server;
    SHA256_CTX hs_hash_client;
    SHA256_CTX hs_hash_server;
    SHA256_CTX hs_hash_client_check;
    SHA256_CTX hs_hash_server_check;
    AES_KEY aes_client;
    AES_KEY aes_server;

    unsigned short version;

} ProxyStates;

ProxyStates *initProxyStates(unsigned short version, EVP_MD *md)
{
    ProxyStates *states = (ProxyStates *)malloc(sizeof(ProxyStates));
    states->version = version;
    states->md = md;
    states->cert_proxy = NULL;
    states->cert_server = NULL;
    states->key_block = (KEY_block *)malloc(sizeof(KEY_block));
    // states->client_HS_buf = (uint8_t *)malloc(BUFSIZE * sizeof(char));
    // states->server_HS_buf = (uint8_t *)malloc(BUFSIZE * sizeof(char));

    SHA256_Init(&states->hs_hash_client);
    SHA256_Init(&states->hs_hash_server);
    SHA256_Init(&states->hs_hash_client_check);
    SHA256_Init(&states->hs_hash_server_check);
    // states->mac_client = HMAC_CTX_new();
    // states->mac_server = HMAC_CTX_new();
    // states->mac_client = EVP_MD_CTX_new();
    // states->mac_server = EVP_MD_CTX_new();
    return states;
}
void freeProxyStates(ProxyStates *states)
{
    // free(states->client_HS_buf);
    // free(states->server_HS_buf);
    free(states->key_block);
    X509_free(states->cert_proxy);
    X509_free(states->cert_server);
    EVP_MD_free(states->md);

    OPENSSL_cleanse(&states->hs_hash_client, sizeof(SHA256_CTX));
    OPENSSL_cleanse(&states->hs_hash_server, sizeof(SHA256_CTX));
    OPENSSL_cleanse(&states->hs_hash_client_check, sizeof(SHA256_CTX));
    OPENSSL_cleanse(&states->hs_hash_server_check, sizeof(SHA256_CTX));
    // HMAC_CTX_free(states->mac_client);
    // HMAC_CTX_free(states->mac_server);
    // EVP_MD_CTX_free(states->mac_client);
    // EVP_MD_CTX_free(states->mac_client);

    free(states);
}

// utils
void print_hex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        if (i % 16 == 0)
        {
            printf(" ");
        }
        printf("%02X", buf[i]);
    }
}
void print_byte(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%s", buf[i]);
    }
}

uint8_t *num_to_byte(size_t num, uint8_t *buffer, size_t buffer_length)
{
    for (int i = buffer_length - 1; i >= 0; i--)
    {
        buffer[i] = num & 0xFF; // 取最低8位
        num >>= 8;              // 向右移动8位
    }
    return buffer;
}
uint8_t *gen_TLS_head(uint8_t type, uint16_t ver, uint16_t len, uint8_t *out)
{
    // uint8_t out[5] = {0};
    num_to_byte(type, out, 1);
    num_to_byte(ver, out + 1, 2);
    num_to_byte(len, out + 3, 2);
    return out;
}
uint8_t *gen_padding(uint8_t len, uint8_t *out)
{
    // uint8_t *padding = (uint8_t *)malloc(len + 1);
    for (uint8_t i = 0; i <= len; i++)
    {
        num_to_byte(len, out + i, 1);
    }
    return out;
}
void print_public_key(X509 *cert)
{
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    if (pubkey)
    {
        switch (EVP_PKEY_id(pubkey))
        {
            case EVP_PKEY_RSA: {
                RSA *rsa = EVP_PKEY_get1_RSA(pubkey);
                if (rsa)
                {
                    printf("公钥(%d)\n", RSA_size(rsa));
                    RSA_print_fp(stdout, rsa, 0);
                }
                RSA_free(rsa);
                break;
            }
            default: printf("未知的公钥类型\n");
        }
        EVP_PKEY_free(pubkey);
    }
}

void print_subject_info(X509 *cert)
{
    X509_NAME *subject_name = X509_get_subject_name(cert);
    if (subject_name)
    {
        int nid;
        char buffer[256];

        // 打印通用名 (Common Name)
        nid = NID_commonName;
        X509_NAME_get_text_by_NID(subject_name, nid, buffer, sizeof(buffer));
        printf("通用名 (Common Name): %s\n", buffer);

        // 打印国家 (C)
        nid = NID_countryName;
        X509_NAME_get_text_by_NID(subject_name, nid, buffer, sizeof(buffer));
        printf("国家 (Country): %s\n", buffer);

        // 打印组织 (O)
        nid = NID_organizationName;
        X509_NAME_get_text_by_NID(subject_name, nid, buffer, sizeof(buffer));
        printf("组织 (Organization): %s\n", buffer);

        // 打印组织单位 (OU)
        nid = NID_organizationalUnitName;
        X509_NAME_get_text_by_NID(subject_name, nid, buffer, sizeof(buffer));
        printf("组织单位 (Organizational Unit): %s\n", buffer);

        // 打印邮箱地址 (Email)
        nid = NID_pkcs9_emailAddress;
        X509_NAME_get_text_by_NID(subject_name, nid, buffer, sizeof(buffer));
        printf("邮箱地址 (Email): %s\n", buffer);
    }
}
int aes128_decrypt(AES_KEY *aes, uint8_t *in, uint8_t *out, int len, uint8_t *key, uint8_t *iv)
{ // TODO:AES_set_*_key in get_keys; encrypt apart
    if (!in || !iv || !out || !key) return -1;
    // AES_KEY aes;
    uint8_t iv_cache[AES_BLOCK_SIZE] = {0};
    memmove(iv_cache, iv, AES_BLOCK_SIZE);
    if (AES_set_decrypt_key(key, AES_BITS_LEN, aes) < 0)
    {
        return -1;
    }
    AES_cbc_encrypt(in, out, len, aes, iv_cache, AES_DECRYPT);
    return 0;
}
int aes128_encrypt(AES_KEY *aes, uint8_t *in, uint8_t *out, int len, uint8_t *key, uint8_t *iv)
{
    if (!in || !iv || !out || !key) return -1;
    // AES_KEY aes;
    uint8_t iv_cache[AES_BLOCK_SIZE] = {0};
    memmove(iv_cache, iv, AES_BLOCK_SIZE);
    if (AES_set_encrypt_key(key, AES_BITS_LEN, aes) < 0)
    {
        return -1;
    }
    AES_cbc_encrypt(in, out, len, aes, iv_cache, AES_ENCRYPT);
    return 0;
}

uint8_t *sha_256(uint8_t *out, const uint8_t *d1, size_t n1, const uint8_t *d2, size_t n2)
{ // TODO: use SHA256_Update apart
    SHA256_CTX c;
    static uint8_t m[SHA256_DIGEST_LENGTH];

    if (out == NULL) out = m;
    SHA256_Init(&c);
    SHA256_Update(&c, d1, n1);
    SHA256_Update(&c, d2, n2);
    SHA256_Final(out, &c);
    OPENSSL_cleanse(&c, sizeof(c));
    return (out);
}

uint8_t *hmac(EVP_MD *md, uint8_t *out, size_t *out_len, uint8_t *key, size_t key_len, uint8_t *in1,
              size_t in1_len, uint8_t *in2, size_t in2_len, uint8_t *in3, size_t in3_len,
              uint8_t *in4, size_t in4_len)
{ // calculate mac
    // TODO: use states->mac_client instead of ctx
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, key_len, md, NULL);
    HMAC_Update(ctx, in1, in1_len);
    HMAC_Update(ctx, in2, in2_len);
    HMAC_Update(ctx, in3, in3_len);
    HMAC_Update(ctx, in4, in4_len);
    HMAC_Final(ctx, out, out_len);
    HMAC_CTX_free(ctx);
    return out;
}
uint8_t *EVP_digest_sign(EVP_MD *md, uint8_t *out, size_t *out_len, uint8_t *key, size_t key_len,
                         uint8_t *in1, size_t in1_len, uint8_t *in2, size_t in2_len, uint8_t *in3,
                         size_t in3_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY *mac_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, key_len);
    // EVP_DigestSignInit(ctx, NULL, md, NULL, mac_key);
    if (EVP_DigestSignInit(ctx, NULL, md, NULL, mac_key) <= 0 ||
        EVP_DigestSignUpdate(ctx, in1, in1_len) <= 0 ||
        EVP_DigestSignUpdate(ctx, in2, in2_len) <= 0 ||
        EVP_DigestSignUpdate(ctx, in3, in3_len) <= 0 || EVP_DigestSignFinal(ctx, out, out_len) <= 0)
    {
        EVP_PKEY_free(mac_key);
        EVP_MD_CTX_free(ctx);
        printf("mac error\n");
        return 0;
    }
    EVP_PKEY_free(mac_key);
    EVP_MD_CTX_free(ctx);
    return 1;
}
uint8_t *EVP_digest_sign_ex(EVP_MD *md, uint8_t *out, size_t *out_len, uint8_t *key, size_t key_len,
                            uint8_t *in1, size_t in1_len, uint8_t *in2, size_t in2_len,
                            uint8_t *in3, size_t in3_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY *mac_key = EVP_PKEY_new_raw_private_key_ex(NULL, "HMAC", NULL, key, key_len);
    // EVP_PKEY *mac_key = EVP_PKEY_new_raw_private_key_ex(libctx, "HMAC", propq, key, key_len);
    // EVP_DigestSignInit(ctx, NULL, md, NULL, mac_key);
    // if (EVP_DigestSignInit_ex(ctx, NULL, EVP_MD_name(md), libctx, propq, mac_key, NULL) <= 0 ||
    if (EVP_DigestSignInit_ex(ctx, NULL, EVP_MD_name(md), NULL, NULL, mac_key, NULL) <= 0 ||
        EVP_DigestSignUpdate(ctx, in1, in1_len) <= 0 ||
        EVP_DigestSignUpdate(ctx, in2, in2_len) <= 0 ||
        EVP_DigestSignUpdate(ctx, in3, in3_len) <= 0 || EVP_DigestSignFinal(ctx, out, out_len) <= 0)
    {
        EVP_PKEY_free(mac_key);
        EVP_MD_CTX_free(ctx);
        printf("mac error\n");
        return 0;
    }
    EVP_PKEY_free(mac_key);
    EVP_MD_CTX_free(ctx);
    return 1;
}
static int tls12_PRF(const EVP_MD *md, uint8_t *out, size_t out_len, const uint8_t *secret,
                     size_t secret_len, const uint8_t *label, size_t label_len,
                     const uint8_t *seed1, size_t seed1_len, const uint8_t *seed2, size_t seed2_len,
                     const uint8_t *seed3, size_t seed3_len)
{
    EVP_PKEY_CTX *pctx = NULL;
    int ret = 0;
    if (md == NULL)
    {
        return 0;
    }
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
    if (pctx == NULL || EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_tls1_prf_md(pctx, md) <= 0 ||
        EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, secret, (int)secret_len) <= 0 ||
        EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, label, (int)label_len) <= 0 ||
        EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed1, (int)seed1_len) <= 0 ||
        EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed2, (int)seed2_len) <= 0 ||
        EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed3, (int)seed3_len) <= 0 ||
        EVP_PKEY_derive(pctx, out, &out_len) <= 0)
    {
        goto err;
    }
    ret = 1;
err:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}
// proxy func
void hash_HS_before(ProxyStates *states, char *src, size_t len, char orient)
{
    if (orient == C2S)
    {
        // memmove(states->client_HS_buf + states->client_HS_len, src, len);
        // states->client_HS_len += len;
        SHA256_Update(&states->hs_hash_client, src, len);
        SHA256_Update(&states->hs_hash_client_check, src, len);
    }
    else
    {
        // memmove(states->server_HS_buf + states->server_HS_len, src, len);
        // states->server_HS_len += len;
        SHA256_Update(&states->hs_hash_server, src, len);
        SHA256_Update(&states->hs_hash_server_check, src, len);
    }
}

void hash_HS_after(ProxyStates *states, uint8_t *src, size_t len, char orient)
{
    if (orient == C2S)
    {
        // memmove(states->server_HS_buf + states->server_HS_len, src, len);
        // states->server_HS_len += len;
        SHA256_Update(&states->hs_hash_server, src, len);
        SHA256_Update(&states->hs_hash_server_check, src, len);
    }
    else
    {
        // memmove(states->client_HS_buf + states->client_HS_len, src, len);
        // states->client_HS_len += len;
        SHA256_Update(&states->hs_hash_client, src, len);
        SHA256_Update(&states->hs_hash_client_check, src, len);
    }
}

int loadCertFile(ProxyStates *states, const char *path)
{
    FILE *cert_file = NULL;
    // 打开证书文件
    cert_file = fopen(path, "rb");
    if (!cert_file)
    {
        fprintf(stderr, "无法打开证书文件\n");
        return errno;
    }
    // 读取证书
    states->cert_proxy = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if (!states->cert_proxy)
    {
        fprintf(stderr, "无法解析证书\n");
        fclose(cert_file);
        return errno;
    }
    // print_subject_info(cert_proxy);
    fclose(cert_file);
    return 0;
}

void praseHandshake(ProxyStates *states, uint8_t *buf, size_t len, char orient)
{
    // handshake type
    uint8_t *p = buf;
    p += TLS_HEAD_LEN;
    unsigned short cipher_suites_length = 2;
    unsigned short start_pos = 1;
    uint8_t session_id_length = p[38];
    // 解析协议版本（5-6 字节）
    printf(" Protocol Version: ");
    print_hex(p + 4, 2);
    printf("\n");

    // 解析会话 ID(39+)
    if (session_id_length > 0)
    {
        printf(" Session ID: ");
        print_hex(p + 39, session_id_length);
        printf("\n");
    }
    // 解析随机数（7-38 字节）
    // printf(" Random: ");
    // uint8_t *random_key=NULL;
    // print_hex(random_key, SSL3_RANDOM_SIZE);
    // printf("\n");
    if (orient == C2S)
    {
        memmove(states->random_client, p + 6, SSL3_RANDOM_SIZE);
        cipher_suites_length = GET_2BYTE(p + 38 + session_id_length + 1);
        // (p[38 + session_id_length + 1] << 8) + p[38 + session_id_length + 2];
        start_pos = 3;
    }
    else
    {
        memmove(states->random_server, p + 6, SSL3_RANDOM_SIZE);
    }

    // 解析加密套件
    printf(" Cipher Suites: ");
    print_hex(p + 38 + session_id_length + start_pos, cipher_suites_length);
    printf("\n");

    // 解析压缩算法
    uint8_t compression_methods_length =
        p[38 + session_id_length + start_pos + cipher_suites_length];
    if (compression_methods_length > 0)
    {
        printf(" Compression Methods: ");
        print_hex(p + 38 + session_id_length + start_pos + cipher_suites_length + 1,
                  compression_methods_length);
        printf("\n");
    }
}

int exchangeCert(ProxyStates *states, char *buf, size_t len, size_t len_left)
{
    uint8_t *bytes_cert_server = buf + 15;
    // len-=15;
    int len_cert_server = len - 15;
    states->cert_server = d2i_X509(NULL, &bytes_cert_server, len_cert_server);

    // 获取证书的二进制比特流
    uint8_t *bytes_cert_proxy = NULL;
    int len_cert_proxy = i2d_X509(states->cert_proxy, &bytes_cert_proxy);
    if (len_cert_proxy > 0)
    {
        // print_hex(buf+15,len_cert_server);
        // copy to buf
        memmove(buf + 15 + len_cert_proxy, buf + 15 + len_cert_server, len_left + 1);
        memmove(buf + 15, bytes_cert_proxy, len_cert_proxy);
        // print_hex(buf+15,len_cert_proxy);

        // set buf lenth
        num_to_byte(len_cert_proxy, buf + 12, 3);
        num_to_byte(len_cert_proxy + 3, buf + 9, 3);
        num_to_byte(len_cert_proxy + 6, buf + 6, 3);
        num_to_byte(len_cert_proxy + 10, buf + 3, 2);

        OPENSSL_free(bytes_cert_proxy);
    }
    else
    {
        fprintf(stderr, "i2d_X509 调用失败\n");
    }
    return len_cert_proxy - len_cert_server;
}

int getKeyBlock(ProxyStates *states, char *buf, size_t len, size_t len_left, char orient)
{
    uint8_t *preMaster_en = buf + 11;
    int len_preMaster_en = len - 11;
    RSA *rsa_prxyPriv = NULL; // 声明RSA结构体
    BIO *bio = NULL;          // 声明BIO结构体

    uint8_t preMaster_de[SSL3_MASTER_SECRET_SIZE] = {0};

    // 从文件中加载私钥
    bio = BIO_new_file(private_key_path, "rb");
    rsa_prxyPriv = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    int decryptedLength = RSA_private_decrypt(len_preMaster_en, preMaster_en, preMaster_de,
                                              rsa_prxyPriv, RSA_PKCS1_PADDING);

    RSA_free(rsa_prxyPriv);
    if (decryptedLength == -1)
    {
        // 解密失败
        printf("解密失败\n");
    }
    else
    {
        // 解密成功
        printf("pms: ");
        print_hex(preMaster_de, SSL3_MASTER_SECRET_SIZE);
        printf("\n");
        // hash_HS_before(states, buf + TLS_HEAD_LEN, len - TLS_HEAD_LEN, orient);

        // uint8_t *encryptedData = NULL;
        // encryptedData = (uint8_t *)malloc(RSA_2048_SIZE);
        uint8_t encryptedData[RSA_2048_SIZE] = {0};

        // 计算PRF
        tls12_PRF(states->md, states->master_secret, SSL3_MASTER_SECRET_SIZE, preMaster_de,
                  SSL3_MASTER_SECRET_SIZE, TLS_MD_MASTER_SECRET_CONST,
                  TLS_MD_MASTER_SECRET_CONST_SIZE, states->random_client, SSL3_RANDOM_SIZE,
                  states->random_server, SSL3_RANDOM_SIZE, NULL, 0);
        tls12_PRF(states->md, (uint8_t *)(states->key_block), sizeof(KEY_block),
                  states->master_secret, SSL3_MASTER_SECRET_SIZE, TLS_MD_KEY_EXPANSION_CONST,
                  TLS_MD_KEY_EXPANSION_CONST_SIZE, states->random_server, SSL3_RANDOM_SIZE,
                  states->random_client, SSL3_RANDOM_SIZE, NULL, 0);
        // printf("randoms:\n");
        // print_hex(random_client, 32);
        // printf("\n");
        // print_hex(random_server, 32);
        // printf("\n");
        printf("keys:\n");
        print_hex(states->master_secret, 48);
        printf("\n");
        print_hex(states->key_block->client_write_key, 16);
        printf("\n");
        print_hex(states->key_block->client_write_MAC_key, 32);
        printf("\n");
        // AES_set_decrypt_key(states->key_block->client_write_key, AES_BITS_LEN,
        // &states->aes_client); AES_set_decrypt_key(states->key_block->server_write_key,
        // AES_BITS_LEN, &states->aes_server);
        //  HMAC_Init_ex(states->mac_client,
        // states->key_block->client_write_MAC_key,
        //              SHA256_DIGEST_LENGTH, states->md, NULL);
        // HMAC_Init_ex(states->mac_server, states->key_block->server_write_MAC_key,
        //              SHA256_DIGEST_LENGTH, states->md, NULL);
        // in cipher spec
        // EVP_PKEY *mac_key = EVP_PKEY_new_raw_private_key(
        //     EVP_PKEY_HMAC, NULL, states->key_block->client_write_MAC_key, 32);
        // EVP_DigestSignInit(states->mac_client, NULL, states->md, NULL, mac_key);
        // mac_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL,
        //                                        states->key_block->client_write_MAC_key, 32);
        // EVP_DigestSignInit(states->mac_server, NULL, states->md, NULL, mac_key);

        // recrypt pms to server
        EVP_PKEY *pubKey = X509_get_pubkey(states->cert_server);
        RSA *rsa_servPub = EVP_PKEY_get1_RSA(pubKey);
        int encryptedLength = RSA_public_encrypt(SSL3_MASTER_SECRET_SIZE, preMaster_de,
                                                 encryptedData, rsa_servPub, RSA_PKCS1_PADDING);

        RSA_free(rsa_servPub);
        EVP_PKEY_free(pubKey);
        if (encryptedLength != len_preMaster_en)
        {
            memmove(buf + 11 + encryptedLength, buf + len, len_left);
        }
        memmove(buf + 11, encryptedData, encryptedLength);

        // hash_HS_after(states, buf + TLS_HEAD_LEN, len - TLS_HEAD_LEN, orient);
        // free(encryptedData);
        return encryptedLength - len_preMaster_en;
    }
}

int reFinish(ProxyStates *states, uint8_t *buf, size_t len, char orient)
{
    // const EVP_MD *md = EVP_sha256();
    // size_t mac_len = len - TLS_HEAD_LEN - AES_BLOCK_SIZE;
    // size_t verify_len = 12;
    uint8_t finish[SHA256_DIGEST_LENGTH] = {0};
    uint8_t recved_finish[SHA256_DIGEST_LENGTH] = {0};
    uint8_t sha[SHA256_DIGEST_LENGTH] = {0};
    uint8_t mac_head[13] = {0};
    uint8_t mac[SHA256_DIGEST_LENGTH] = {0};
    uint8_t encrypted_finish[32] = {0};
    // uint8_t *recved_finish = (uint8_t *)malloc(len - TLS_HEAD_LEN - AES_BLOCK_SIZE);
    uint8_t *iv = buf + TLS_HEAD_LEN;

    num_to_byte(SSL3_MT_FINISHED, finish, 1);
    num_to_byte(TLS1_FINISH_MAC_LENGTH, finish + 1, 3);
    num_to_byte(0, mac_head, 8);
    gen_TLS_head(SSL3_RT_HANDSHAKE, states->version, 48, mac_head + 8);
    gen_padding(15, finish + 16);

    if (orient == C2S)
    {
        aes128_decrypt(&states->aes_server, iv + AES_BLOCK_SIZE, recved_finish,
                       SHA256_DIGEST_LENGTH, states->key_block->client_write_key, iv);
        print_hex(recved_finish, SHA256_DIGEST_LENGTH);
        printf("\n");
        SHA256_Final(sha, &states->hs_hash_client_check);
        tls12_PRF(states->md, finish + 4, TLS1_FINISH_MAC_LENGTH, states->master_secret,
                  SSL3_MASTER_SECRET_SIZE, TLS_MD_CLIENT_FINISH_CONST,
                  TLS_MD_CLIENT_FINISH_CONST_SIZE, sha, SHA256_DIGEST_LENGTH, NULL, 0, NULL, 0);
        print_hex(finish, SHA256_DIGEST_LENGTH);
        printf("\n");

        SHA256_Final(sha, &states->hs_hash_server);
        tls12_PRF(states->md, finish + 4, TLS1_FINISH_MAC_LENGTH, states->master_secret,
                  SSL3_MASTER_SECRET_SIZE, TLS_MD_CLIENT_FINISH_CONST,
                  TLS_MD_CLIENT_FINISH_CONST_SIZE, sha, SHA256_DIGEST_LENGTH, NULL, 0, NULL, 0);
        // aes128_decrypt(&states->aes_client, buf + TLS_HEAD_LEN + AES_BLOCK_SIZE, recved_finish,
        //                len - TLS_HEAD_LEN - AES_BLOCK_SIZE, states->key_block->client_write_key,
        //                buf + TLS_HEAD_LEN);
        aes128_encrypt(&states->aes_client, finish, encrypted_finish, SHA256_DIGEST_LENGTH,
                       states->key_block->client_write_key, iv);
        // print_hex(encrypted_finish, SHA256_DIGEST_LENGTH);
        // printf("\n");
        hmac(states->md, mac, NULL, states->key_block->client_write_MAC_key, SHA256_DIGEST_LENGTH,
             mac_head, sizeof(mac_head), iv, AES_BLOCK_SIZE, encrypted_finish, SHA256_DIGEST_LENGTH,
             NULL, 0);
    }
    else
    {
        aes128_decrypt(&states->aes_server, iv + AES_BLOCK_SIZE, recved_finish,
                       SHA256_DIGEST_LENGTH, states->key_block->server_write_key, iv);
        print_hex(recved_finish, SHA256_DIGEST_LENGTH);
        printf("\n");
        SHA256_Final(sha, &states->hs_hash_server_check);
        tls12_PRF(states->md, finish + 4, TLS1_FINISH_MAC_LENGTH, states->master_secret,
                  SSL3_MASTER_SECRET_SIZE, TLS_MD_SERVER_FINISH_CONST,
                  TLS_MD_SERVER_FINISH_CONST_SIZE, sha, SHA256_DIGEST_LENGTH, NULL, 0, NULL, 0);
        print_hex(finish, SHA256_DIGEST_LENGTH);
        printf("\n");

        SHA256_Final(sha, &states->hs_hash_client);
        tls12_PRF(states->md, finish + 4, TLS1_FINISH_MAC_LENGTH, states->master_secret,
                  SSL3_MASTER_SECRET_SIZE, TLS_MD_SERVER_FINISH_CONST,
                  TLS_MD_SERVER_FINISH_CONST_SIZE, sha, SHA256_DIGEST_LENGTH, NULL, 0, NULL, 0);
        // print_hex(finish, SHA256_DIGEST_LENGTH);
        // printf("\n");
        aes128_encrypt(&states->aes_server, finish, encrypted_finish, SHA256_DIGEST_LENGTH,
                       states->key_block->server_write_key, iv);
        hmac(states->md, mac, NULL, states->key_block->server_write_MAC_key, SHA256_DIGEST_LENGTH,
             mac_head, sizeof(mac_head), iv, AES_BLOCK_SIZE, encrypted_finish, SHA256_DIGEST_LENGTH,
             NULL, 0);
    }

    // print_hex(buf + TLS_HEAD_LEN, 16); // iv
    // printf("\n");
    // print_hex(buf + TLS_HEAD_LEN + AES_BLOCK_SIZE, len - TLS_HEAD_LEN - AES_BLOCK_SIZE);
    // printf("\n");
    print_hex(finish, 32);
    printf("\n");
    print_hex(mac, SHA256_DIGEST_LENGTH);
    printf("\n");

    memmove(buf + TLS_HEAD_LEN + AES_BLOCK_SIZE, encrypted_finish, SHA256_DIGEST_LENGTH);
    memmove(buf + TLS_HEAD_LEN + AES_BLOCK_SIZE + SHA256_DIGEST_LENGTH, mac, SHA256_DIGEST_LENGTH);

    hash_HS_before(states, recved_finish, AES_BLOCK_SIZE, orient);
    hash_HS_after(states, finish, AES_BLOCK_SIZE, orient);

    // free(recved_finish);
}

// int newSessionTicketExchange(ProxyStates *states, uint8_t *buf, size_t len, size_t len_left,
//                              char orient)
// {
//     size_t lenPlaintext = len - 5 - 4 - 64 - 6;
//     uint8_t *statePlaintext = (uint8_t *)malloc(lenPlaintext);
//     uint8_t cache[160] = {0};
//     aes128_decrypt(&states->aes_server, buf + TLS_HEAD_LEN + HS_HEAD_LEN + 32 + 6, statePlaintext,
//                    lenPlaintext, states->key_block->server_write_key, buf + 5 + 4 + 6 + 16);
//     for (size_t i = 128; i > 32; i -= 16)
//     {
//         aes128_decrypt(&states->aes_server, buf + (len - i), cache, i - 32,
//                        states->key_block->server_write_key, buf + 5 + 4 + 6 + 16);
//         print_hex(buf + (len - 128), i - 32);
//         printf("\n");
//         print_hex(cache, i - 32);
//         printf("\n");
//     }
//     // print_hex(buf + TLS_HEAD_LEN + HS_HEAD_LEN + 32 + 6, lenPlaintext);
//     // printf("\n");
//     // print_hex(statePlaintext, lenPlaintext);
//     // printf("\n");

//     free(statePlaintext);
// }
int deApplication(ProxyStates *states, uint8_t *buf, size_t len, size_t len_left,
                             char orient){

}
int handleMsg(ProxyStates *states, char *buf, size_t len, char orient)
{
    uint8_t *p = NULL;
    size_t i = 0;
    char finished = 0;
    uint8_t content_type = 0;
    unsigned short content_lenth = 0;
    int diff = 0;
    while (i < len)
    {
        p = buf + i;
        content_type = p[0];
        content_lenth = GET_2BYTE(p + 3) + TLS_HEAD_LEN;

        if (content_type == SSL3_RT_HANDSHAKE)
        { // Handshake message
            // ommit
            if (p[TLS_HEAD_LEN] == SSL3_MT_HELLO_REQUEST)
            {
                printf("Hello Request\n");
                goto nextContent;
            }
            else if (p[TLS_HEAD_LEN] == SSL3_MT_FINISHED || finished == SSL3_MT_FINISHED)
            {
                printf("Finished\n");
                reFinish(states, p, content_lenth, orient);
                finished = 0;
                // hash_HS_after(states, p + TLS_HEAD_LEN, content_lenth - TLS_HEAD_LEN - 32,
                // orient);
                goto nextContent;
            }

            // encrypt
            hash_HS_before(states, p + TLS_HEAD_LEN, content_lenth - TLS_HEAD_LEN, orient);

            if (p[TLS_HEAD_LEN] == SSL3_MT_CLIENT_KEY_EXCHANGE)
            {
                printf("Client Key Exchange:\n");
                diff = getKeyBlock(states, p, content_lenth, len - i - content_lenth, orient);

                content_lenth += diff;
                len += diff;
                // goto nextContent;
            }
            // plaintext
            // hash_HS_before(states, p + TLS_HEAD_LEN, content_lenth - TLS_HEAD_LEN, orient);
            else if (p[TLS_HEAD_LEN] == SSL3_MT_CLIENT_HELLO)
            { // Client Hello
                printf("Client Hello:\n");
                praseHandshake(states, p, content_lenth, orient);
            }
            else if (p[TLS_HEAD_LEN] == SSL3_MT_SERVER_HELLO)
            { // Server Hello
                printf("Server Hello:\n");
                praseHandshake(states, p, content_lenth, orient);
            }
            else if (p[TLS_HEAD_LEN] == SSL3_MT_NEWSESSION_TICKET)
            {
                printf("New Session Ticket:\n");
                // newSessionTicketExchange(states, p, content_lenth, len - i - content_lenth, orient);
            }
            else if (p[TLS_HEAD_LEN] == SSL3_MT_CERTIFICATE)
            {
                printf("Certificate:\n");

                diff = exchangeCert(states, p, content_lenth, len - i - content_lenth);
                content_lenth += diff;
                len += diff;
            }
            else if (p[TLS_HEAD_LEN] == SSL3_MT_SERVER_KEY_EXCHANGE)
            {
                printf("Server Key Exchange:\n");
            }
            else if (p[TLS_HEAD_LEN] == SSL3_MT_CERTIFICATE_REQUEST)
            {
                printf("Certificate Request:\n");
            }
            else if (p[TLS_HEAD_LEN] == SSL3_MT_SERVER_DONE)
            {
                printf("Server Hello Done:\n");
            }
            else if (p[TLS_HEAD_LEN] == SSL3_MT_CERTIFICATE_VERIFY)
            {
                printf("Certificate Verify:\n");
            }

            hash_HS_after(states, p + TLS_HEAD_LEN, content_lenth - TLS_HEAD_LEN, orient);
        }
        else if (content_type == SSL3_RT_CHANGE_CIPHER_SPEC)
        {
            printf("ChangeCipherSpec\n");
            finished = 20;
        }
        else if (content_type == SSL3_RT_ALERT)
        {
            printf("Alert\n");
        }
        else if (content_type == SSL3_RT_APPLICATION_DATA)
        {
            printf("Application\n");
        }
    nextContent:
        i += content_lenth;
    }
    return len;
}

int reHandshake(ProxyStates *states)
{
    SHA256_Init(&states->hs_hash_client);
    SHA256_Init(&states->hs_hash_server);
    SHA256_Init(&states->hs_hash_client_check);
    SHA256_Init(&states->hs_hash_server_check);
}

int trans(ProxyStates *states, int sock_from, int sock_to, uint8_t *transBuf, char orient)
{
    int recvBytes = 0;
    int totalTransBytes = 0;
    int retryCount = 0;
    int sendBytes = 0;
    while (1)
    {
        recvBytes = recv(sock_from, transBuf, BUFSIZE, 0);
        if (recvBytes > 0)
        {
            retryCount = 0;
            totalTransBytes += recvBytes;
            recvBytes = handleMsg(states, transBuf, recvBytes, orient);
            // send here
            sendBytes = send(sock_to, transBuf, recvBytes, 0);
            if (sendBytes < 0)
            {
                printf("send failed\n");
                break;
            }
        }
        else if (recvBytes == 0)
        {
            printf("recv closed:%d %d\n", recvBytes, errno);
            break;
        }
        else
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                if (retryCount < MAX_RETRY)
                {
                    retryCount++;
                    // printf("%d ", retryCount);
                    usleep(2000);
                    continue;
                }
                else
                {
                    printf("max retry, recv finished:%d %d\n", recvBytes, errno);
                    break;
                }
            }
            else
            {
                printf("%s %d recv error=%d\n", __func__, __LINE__, errno);
                break;
            }
        }
    }
    return totalTransBytes;
}

int socketInit2Clnt(int *fd, struct sockaddr_in *pAddr, socklen_t len)
{
    // as a server
    pAddr->sin_family = AF_INET;
    pAddr->sin_addr.s_addr = htonl(INADDR_ANY); // ip地址
    pAddr->sin_port = htons(PORT2CLNT);         // 绑定端口
    *fd = socket(AF_INET, SOCK_STREAM, 0);
    if (*fd < 0)
    {
        printf("%s(%d)socket to clnt error:%d\n", __func__, __LINE__, errno);
        return errno;
    }
    if (bind(*fd, (struct sockaddr *)pAddr, len) < 0)
    {
        printf("%s(%d)failed bind to clnt:%d\n", __func__, __LINE__, errno);
        return errno;
    }
    if (listen(*fd, BACKLOG) < 0)
    {
        printf("%s(%d)listen to clnt failed:%d\n", __func__, __LINE__, errno);
        return errno;
    }
    return 0;
}

int socketInit2Serv(int *fd, char *ip, struct sockaddr_in *pAddr)
{
    inet_pton(AF_INET, ip, &(pAddr->sin_addr));
    // proxyAddr2Serv.sin_addr.s_addr = clntAddr.sin_addr.s_addr;
    pAddr->sin_family = AF_INET;
    pAddr->sin_port = htons(PORT2SERV);
    *fd = socket(AF_INET, SOCK_STREAM, 0);
    if (*fd < 0)
    {
        printf("%s(%d)socket to serv error: %d\n", __func__, __LINE__, errno);
        return errno;
    }
    return 0;
}

int main()
{
    int proxySocket = -1;
    struct sockaddr_in proxyAddr = {0};
    socklen_t addrSize = sizeof(struct sockaddr);
    int proxyConn2Clnt = -1;
    struct sockaddr_in clntAddr = {0};
    int proxySocket2Serv = -1;
    struct sockaddr_in proxyAddr2Serv = {0};

    ProxyStates *states = initProxyStates(TLS1_2_VERSION, EVP_sha256());

    uint8_t *transBuf = (uint8_t *)malloc(BUFSIZE * sizeof(char));
    // char ipBuf[16] = "192.168.137.1";
    char ipBuf[16] = "127.0.0.1";

    // int nonBlockFlags = 0;
    struct timeval timeout;
    timeout.tv_sec = 5; // 设置超时为5秒
    timeout.tv_usec = 0;

    int epoll_fd = -1;
    int epoll_ready = 0;
    struct epoll_event event, events[MAX_EVENTS];

    do
    {
        if ( // load cert
            loadCertFile(states, certificate_path) != 0)
        {
            break;
        }
        // print_subject_info(cert_proxy);
        if ( // init socket to clinent
            socketInit2Clnt(&proxySocket, &proxyAddr, addrSize) != 0)
        {
            break;
        }
        // 创建epoll实例
        epoll_fd = epoll_create1(0);
        if (epoll_fd == -1)
        {
            printf("%s(%d)Epoll creation failed:%d\n", __func__, __LINE__, errno);
            break;
        }

        // 注册服务器socket到epoll
        event.events = EPOLLIN;
        event.data.fd = proxySocket;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, proxySocket, &event) == -1)
        {
            printf("%s(%d)Epoll control error:%d\n", __func__, __LINE__, errno);
            break;
        }
        printf("proxy listening...\n");
        // maybe new thread
        while (1)
        {
            epoll_ready = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

            if (epoll_ready < 0)
            {
                printf("%s(%d)Epoll wait error:%d\n", __func__, __LINE__, errno);
                continue;
            }
            for (int i = 0; i < epoll_ready; i++)
            {
                if (events[i].data.fd == proxySocket)
                {
                    // 有新的连接请求
                    proxyConn2Clnt = -1;
                    proxyConn2Clnt = accept(proxySocket, (struct sockaddr *)&clntAddr, &addrSize);
                    if (proxyConn2Clnt < 0)
                    {
                        printf("%s(%d)Accept failed:%d\n", __func__, __LINE__, errno);
                        continue;
                    }
                    else
                    {
                        printf("\nNew Client %d...\n", proxyConn2Clnt);
                    }
                    setsockopt(proxyConn2Clnt, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                               sizeof(timeout)); // 超时返回-1

                    // 将客户端socket注册到epoll
                    event.events = EPOLLIN;
                    event.data.fd = proxyConn2Clnt;
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, proxyConn2Clnt, &event) == -1)
                    {
                        printf("%s(%d)Epoll control error:%d\n", __func__, __LINE__, errno);
                        close(proxyConn2Clnt);
                        continue;
                    }
                }
                else
                {
                    proxySocket2Serv = -1;

                    do
                    {
                        if (socketInit2Serv(&proxySocket2Serv, ipBuf, &proxyAddr2Serv) != 0)
                        {
                            break;
                        }
                        setsockopt(proxySocket2Serv, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                                   sizeof(timeout)); // 超时返回-1
                        if (connect(proxySocket2Serv, (struct sockaddr *)&proxyAddr2Serv,
                                    addrSize) < 0)
                        {
                            printf("%s(%d)Connect to server failed: %d\n", __func__, __LINE__,
                                   errno);
                            close(proxySocket2Serv);
                            break;
                        }
#if nonBlockMode
                        //
                        int nonBlockFlagsS = fcntl(proxySocket2Serv, F_GETFL, 0);
                        int nonBlockFlagsC = fcntl(events[i].data.fd, F_GETFL, 0);
#endif
                        // 有数据可读
                        while (1)
                        {
                            memset(transBuf, '\0', sizeof(transBuf));

                            int retryCount = 0;
                            int transBytes = 0;
                            int recvBytes = 0;
                            int sendBytes = 0;
                            recvBytes = recv(events[i].data.fd, transBuf, BUFSIZE, 0);
                            if (recvBytes > 0)
                            {
                                retryCount = 0;
                                transBytes += recvBytes;
                                recvBytes = handleMsg(states, transBuf, recvBytes, C2S);
                                // printf("%s", transBuf);
                                sendBytes = send(proxySocket2Serv, transBuf, recvBytes, 0);
                                if (sendBytes < 0)
                                {
                                    printf("Send failed\n");
                                    break;
                                }
                            }
                            else if (recvBytes == 0)
                            {
                                // 客户端断开连接或出错
                                printf("Disconnected:%d %d\n", recvBytes, errno);
                                break;
                            }
                            else
                            {
                                if (errno == EAGAIN || errno == EWOULDBLOCK)
                                {
                                    if (retryCount < MAX_RETRY)
                                    {
                                        retryCount++;
                                        usleep(1000);
                                        continue;
                                    }
                                    else
                                    {
                                        printf("Max retry:%d %d\n", recvBytes, errno);
                                        break;
                                    }
                                    // continue;
                                }
                                printf("Connect error:%d %d\n", recvBytes, errno);
                                break;
                            }

#if nonBlockMode
                            fcntl(events[i].data.fd, F_SETFL, nonBlockFlagsC | O_NONBLOCK);
#endif
                            transBytes +=
                                trans(states, events[i].data.fd, proxySocket2Serv, transBuf, C2S);
                            printf("Recv:(%d)\n", transBytes);
#if nonBlockMode
                            fcntl(events[i].data.fd, F_SETFL, nonBlockFlagsC & ~O_NONBLOCK);
                            fcntl(proxySocket2Serv, F_SETFL, nonBlockFlagsS | O_NONBLOCK);
#endif
                            transBytes = 0;
                            transBytes +=
                                trans(states, proxySocket2Serv, events[i].data.fd, transBuf, S2C);
                            printf("Recv:(%d)\n", transBytes);
#if nonBlockMode
                            fcntl(proxySocket2Serv, F_SETFL, nonBlockFlagsS & ~O_NONBLOCK);
#endif
                        }
                    } while (0);
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                    if (events[i].data.fd > 0)
                    {
                        close(events[i].data.fd);
                    }
                    reHandshake(states);
                }
            }
        }

    } while (0);

    if (proxyConn2Clnt > 0)
    {
        close(proxyConn2Clnt);
    }
    if (proxySocket > 0)
    {
        close(proxySocket);
    }
    if (proxySocket2Serv > 0)
    {
        close(proxySocket2Serv);
    }
    free(transBuf);
    freeProxyStates(states);
    free(states);
    return 0;
}