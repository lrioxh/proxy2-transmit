// TODO
// clean code
// 1. Get and replace server cert(publicKey) o
// 2. get PMS from client, decrypt, encrypt again using proxy key, o
//    generate MS and SK
// 3. calculate MAC

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
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

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

typedef struct
{
    uint8_t client_write_MAC_key[SHA256_DIGEST_LENGTH];
    uint8_t server_write_MAC_key[SHA256_DIGEST_LENGTH];
    uint8_t client_write_key[AES_BLOCK_SIZE];
    uint8_t server_write_key[AES_BLOCK_SIZE];
    // uint8_t client_write_IV[AES_BLOCK_SIZE];
    // uint8_t server_write_IV[AES_BLOCK_SIZE];
} KEY_block;

typedef struct
{
    const EVP_MD *md;
    X509 *cert_proxy;
    X509 *cert_server;
    KEY_block *key_block;
    uint8_t *client_HS_buf;
    uint8_t *server_HS_buf;
    size_t client_HS_len;
    size_t server_HS_len;
    uint8_t random_server[SSL3_RANDOM_SIZE];
    uint8_t random_client[SSL3_RANDOM_SIZE];
    uint8_t master_secret[SSL3_MASTER_SECRET_SIZE];

    SHA256_CTX *hash_client;
    SHA256_CTX *hash_server;
    HMAC_CTX *mac_client;
    HMAC_CTX *mac_server;
    AES_KEY aes_client;
    AES_KEY aes_server;

} ProxyParams;
void initProxyParams(ProxyParams *params, EVP_MD *md)
{
    params = (ProxyParams *)malloc(sizeof(ProxyParams));
    params->md = md;
    params->key_block = (KEY_block *)malloc(sizeof(KEY_block));
    params->client_HS_buf = (uint8_t *)malloc(BUFSIZE * sizeof(char));
    params->server_HS_buf = (uint8_t *)malloc(BUFSIZE * sizeof(char));

    SHA256_Init(params->hash_client);
    SHA256_Init(params->hash_server);
    params->mac_client = HMAC_CTX_new();
    params->mac_server = HMAC_CTX_new();
}
void freeProxyParams(ProxyParams *params)
{
    free(params->client_HS_buf);
    free(params->server_HS_buf);
    free(params->key_block);
    X509_free(params->cert_proxy);
    X509_free(params->cert_server);
    EVP_MD_free(params->md);

    OPENSSL_cleanse(params->hash_client, sizeof(SHA256_CTX));
    OPENSSL_cleanse(params->hash_server, sizeof(SHA256_CTX));
    HMAC_CTX_free(params->mac_client);
    HMAC_CTX_free(params->mac_server);
}

void print_hex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
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
int aes128_decrypt(uint8_t *in, int len, uint8_t *key, uint8_t *iv, uint8_t *out)
{
    if (!in || !key || !out) return 0;
    AES_KEY aes;
    if (AES_set_decrypt_key(key, AES_BITS_LEN, &aes) < 0)
    {
        return 0;
    }
    AES_cbc_encrypt(in, out, len, &aes, iv, AES_DECRYPT);
    return 1;
}
int aes128_encrypt(uint8_t *in, int len, uint8_t *key, uint8_t *iv, uint8_t *out)
{
    if (!in || !key || !out) return 0;
    AES_KEY aes;
    if (AES_set_encrypt_key(key, AES_BITS_LEN, &aes) < 0)
    {
        return 0;
    }
    AES_cbc_encrypt(in, out, len, &aes, iv, AES_ENCRYPT);
    return 1;
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

int cert_exchange(ProxyParams *params, char *buf, size_t len, size_t len_left)
{
    uint8_t *bytes_cert_server = buf + 15;
    // len-=15;
    int len_cert_server = len - 15;
    params->cert_server = d2i_X509(NULL, &bytes_cert_server, len_cert_server);

    // 获取证书的二进制比特流
    uint8_t *bytes_cert_proxy = NULL;
    int len_cert_proxy = i2d_X509(params->cert_proxy, &bytes_cert_proxy);
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

void prase_handshake(const uint8_t *buf, size_t len, uint8_t *random_key)
{
    // handshake type
    // buf += TLS_HEAD_LEN;
    uint8_t handshake_type = buf[0];
    // 解析协议版本（5-6 字节）
    // unsigned short protocol_version = (buf[4] << 8) + buf[5];
    // printf("Protocol Version: %04X\n", protocol_version);
    printf(" Protocol Version: ");
    print_hex(buf + 4, 2);
    printf("\n");

    // 解析随机数（7-38 字节）
    // printf(" Random: ");
    // uint8_t *random_key=NULL;
    memmove(random_key, buf + 6, SSL3_RANDOM_SIZE);
    // print_hex(random_key, SSL3_RANDOM_SIZE);

    printf("\n");

    // 解析会话 ID(39+)
    uint8_t session_id_length = buf[38];
    if (session_id_length > 0)
    {
        printf(" Session ID: ");
        print_hex(buf + 39, session_id_length);
        printf("\n");
    }

    // 解析加密套件
    unsigned short cipher_suites_length = 2;
    unsigned short start_pos = 1;
    // printf("%d",buf[40]);
    if (handshake_type == 1)
    {
        // printf("%d %d",(buf[38 + session_id_length + 1] << 8),buf[38 +
        // session_id_length + 2]);
        cipher_suites_length =
            (buf[38 + session_id_length + 1] << 8) + buf[38 + session_id_length + 2];
        start_pos = 3;
    }
    // print_hex(buf+39,2);
    printf(" Cipher Suites: ");
    print_hex(buf + 38 + session_id_length + start_pos, cipher_suites_length);
    printf("\n");

    // 解析压缩算法
    uint8_t compression_methods_length =
        buf[38 + session_id_length + start_pos + cipher_suites_length];
    if (compression_methods_length > 0)
    {
        printf(" Compression Methods: ");
        print_hex(buf + 38 + session_id_length + start_pos + cipher_suites_length + 1,
                  compression_methods_length);
        printf("\n");
    }
}
int get_keys(ProxyParams *params, char *buf, size_t len, size_t len_left, char orient)
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
        write_HS_buf_before(params, buf + TLS_HEAD_LEN, 1, orient); // type
        write_HS_buf_before(params, buf + TLS_HEAD_LEN, 1, orient); // len1

        // const EVP_MD *md = EVP_sha256(); // 哈希函数

        uint8_t *encryptedData = NULL;
        encryptedData = (uint8_t *)malloc(RSA_2048_SIZE);

        // 计算PRF
        tls12_PRF(params->md, params->master_secret, SSL3_MASTER_SECRET_SIZE, preMaster_de,
                  SSL3_MASTER_SECRET_SIZE, TLS_MD_MASTER_SECRET_CONST,
                  TLS_MD_MASTER_SECRET_CONST_SIZE, params->random_client, SSL3_RANDOM_SIZE,
                  params->random_server, SSL3_RANDOM_SIZE, NULL, 0);
        tls12_PRF(params->md, (uint8_t *)(params->key_block), sizeof(KEY_block),
                  params->master_secret, SSL3_MASTER_SECRET_SIZE, TLS_MD_KEY_EXPANSION_CONST,
                  TLS_MD_KEY_EXPANSION_CONST_SIZE, params->random_server, SSL3_RANDOM_SIZE,
                  params->random_client, SSL3_RANDOM_SIZE, NULL, 0);
        // printf("randoms:\n");
        // print_hex(random_client, 32);
        // printf("\n");
        // print_hex(random_server, 32);
        // printf("\n");
        printf("keys:\n");
        print_hex(params->master_secret, 48);
        printf("\n");
        // print_hex((uint8_t *)&key_block, sizeof(key_block));
        // printf("\n");
        // recrypt pms to server
        EVP_PKEY *pubKey = X509_get_pubkey(params->cert_server);
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
        free(encryptedData);
        return encryptedLength - len_preMaster_en;
    }
}

void write_HS_buf_before(ProxyParams *params, char *src, size_t len, char orient)
{
    if (orient == C2S)
    {
        memmove(params->client_HS_buf + params->client_HS_len, src, len);
        params->client_HS_len += len;
    }
    else
    {
        memmove(params->server_HS_buf + params->server_HS_len, src, len);
        params->server_HS_len += len;
    }
}

void write_HS_buf_after(ProxyParams *params, uint8_t *src, size_t len, char orient)
{
    if (orient == C2S)
    {
        memmove(params->server_HS_buf + params->server_HS_len, src, len);
        params->server_HS_len += len;
    }
    else
    {
        memmove(params->client_HS_buf + params->client_HS_len, src, len);
        params->client_HS_len += len;
    }
}

uint8_t *sha_256(uint8_t *out, const uint8_t *d1, size_t n1, const uint8_t *d2, size_t n2)
{
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
              size_t in1_len, uint8_t *in2, size_t in2_len)
{
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, key_len, md, NULL);
    HMAC_Update(ctx, in1, in1_len);
    HMAC_Update(ctx, in2, in2_len);
    HMAC_Final(ctx, out, out_len);
    HMAC_CTX_free(ctx);
    return out;
}

int reFinish(ProxyParams *params, uint8_t *buf, size_t len, char orient)
{
    // const EVP_MD *md = EVP_sha256();
    // size_t mac_len = len - TLS_HEAD_LEN - AES_BLOCK_SIZE;
    size_t mac_len = 64;
    uint8_t *mac = (uint8_t *)malloc(mac_len);
    uint8_t sha[SHA256_DIGEST_LENGTH] = {0};
    if (orient == C2S)
    {
        // print_hex(params->client_HS_buf, params->client_HS_len);
        printf("\n");
        sha_256(sha, params->client_HS_buf, params->client_HS_len, NULL, 0);
        tls12_PRF(params->md, mac, mac_len, params->master_secret, SSL3_MASTER_SECRET_SIZE,
                  TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE, sha,
                  SHA256_DIGEST_LENGTH, NULL, 0, NULL, 0);
    }
    else
    {
        sha_256(sha, params->server_HS_buf, params->server_HS_len, NULL, 0);
        tls12_PRF(params->md, mac, mac_len, params->master_secret, SSL3_MASTER_SECRET_SIZE,
                  TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE, sha,
                  SHA256_DIGEST_LENGTH, NULL, 0, NULL, 0);
    }
    print_hex(mac, mac_len);
    printf("\n");
    // memmove(buf + 11, mac, encryptedLength);
    free(mac);
}

int handleMsg(ProxyParams *params, char *buf, size_t len, char orient)
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

        if (content_type == 22)
        { // Handshake message
            // ommit
            if (p[TLS_HEAD_LEN] == 0)
            {
                printf("Hello Request\n");
                goto nextContent;
            }

            // encrypt
            // write_HS_buf_before(p + TLS_HEAD_LEN, content_lenth -
            // TLS_HEAD_LEN,
            //                     orient);
            if (p[TLS_HEAD_LEN] == 16)
            {
                printf("Client Key Exchange:\n");
                diff = get_keys(params, p, content_lenth, len - i - content_lenth, orient);

                content_lenth += diff;
                len += diff;
                goto nextContent;
            }
            else if (p[TLS_HEAD_LEN] == 20 || finished == 20)
            {
                printf("Finished\n");
                // print_hex(p, content_lenth);
                // printf("\n");
                reFinish(params, p, content_lenth, orient);
                uint8_t *out = (uint8_t *)malloc(content_lenth - TLS_HEAD_LEN - AES_BLOCK_SIZE);
                // out=(uint8_t*)malloc(content_lenth-
                // TLS_HEAD_LEN-AES_BLOCK_SIZE);
                if (orient == C2S)
                {
                    char iv[AES_BLOCK_SIZE] = {0};
                    memmove(iv, p + TLS_HEAD_LEN, AES_BLOCK_SIZE);

                    // print_hex((uint8_t *)&key_block.client_write_key,
                    //           sizeof(key_block.client_write_key));
                    aes128_decrypt(p + TLS_HEAD_LEN + AES_BLOCK_SIZE,
                                   content_lenth - TLS_HEAD_LEN - AES_BLOCK_SIZE,
                                   params->key_block->client_write_key, iv, out);

                    print_hex(out, content_lenth - TLS_HEAD_LEN - AES_BLOCK_SIZE);
                    printf("\n");
                    free(out);
                }
                else
                {
                    // AES_set_decrypt_key(key_block.server_write_key,
                    //                     AES_BLOCK_SIZE * 8, &aes_key);
                    // AES_cbc_encrypt(p + TLS_HEAD_LEN, out, 80, &aes_key,
                    //                 key_block.server_write_IV, AES_DECRYPT);
                }
                finished = 0;
                goto nextContent;
            }

            // plaintext
            write_HS_buf_before(params, p + TLS_HEAD_LEN, content_lenth - TLS_HEAD_LEN, orient);
            if (p[TLS_HEAD_LEN] == 1)
            { // Client Hello
                printf("Client Hello:\n");
                prase_handshake(p + TLS_HEAD_LEN, content_lenth - TLS_HEAD_LEN,
                                params->random_client);
            }
            else if (p[TLS_HEAD_LEN] == 2)
            { // Server Hello
                printf("Server Hello:\n");
                prase_handshake(p + TLS_HEAD_LEN, content_lenth - TLS_HEAD_LEN,
                                params->random_server);
            }
            else if (p[TLS_HEAD_LEN] == 4)
            {
                printf("New Session Ticket:\n");
            }
            else if (p[TLS_HEAD_LEN] == 11)
            {
                printf("Certificate:\n");

                diff = cert_exchange(params, p, content_lenth, len - i - content_lenth);
                content_lenth += diff;
                len += diff;
            }
            else if (p[TLS_HEAD_LEN] == 12)
            {
                printf("Server Key Exchange:\n");
            }
            else if (p[TLS_HEAD_LEN] == 13)
            {
                printf("Certificate Request:\n");
            }
            else if (p[TLS_HEAD_LEN] == 14)
            {
                printf("Server Hello Done:\n");
            }
            else if (p[TLS_HEAD_LEN] == 15)
            {
                printf("Certificate Verify:\n");
            }

            write_HS_buf_after(params, p + TLS_HEAD_LEN, content_lenth - TLS_HEAD_LEN, orient);
        }
        else if (content_type == 20)
        {
            printf("ChangeCipherSpec\n");
            finished = 20;
        }
        else if (content_type == 21)
        {
            printf("Alert\n");
        }
        else if (content_type == 23)
        {
            printf("Application\n");
        }
    nextContent:
        i += content_lenth;
    }
    return len;
}

int trans(ProxyParams *params, int sock_from, int sock_to, uint8_t *transBuf, char orient)
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
            recvBytes = handleMsg(params, transBuf, recvBytes, orient);
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

int loadCertFile(ProxyParams *params, const char *path)
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
    params->cert_proxy = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if (!params->cert_proxy)
    {
        fprintf(stderr, "无法解析证书\n");
        fclose(cert_file);
        return errno;
    }
    // print_subject_info(cert_proxy);
    fclose(cert_file);
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

    ProxyParams *params = NULL;
    initProxyParams(params, EVP_sha256());

    uint8_t *transBuf;
    transBuf = (uint8_t *)malloc(BUFSIZE * sizeof(char));
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
            loadCertFile(params, certificate_path) != 0)
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
                                recvBytes = handleMsg(params, transBuf, recvBytes, C2S);
                                printf("%s", transBuf);
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
                                trans(params, events[i].data.fd, proxySocket2Serv, transBuf, C2S);
                            printf("Recv:(%d)\n", transBytes);
#if nonBlockMode
                            fcntl(events[i].data.fd, F_SETFL, nonBlockFlagsC & ~O_NONBLOCK);
                            fcntl(proxySocket2Serv, F_SETFL, nonBlockFlagsS | O_NONBLOCK);
#endif
                            transBytes = 0;
                            transBytes +=
                                trans(params, proxySocket2Serv, events[i].data.fd, transBuf, S2C);
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
    freeProxyParams(params);
    free(params);
    return 0;
}