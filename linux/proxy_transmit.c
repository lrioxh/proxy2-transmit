// TODO
// clean code
// 1. Get and replace server cert(publicKey)
// 2. get PMS from client, decrypt, encrypt again using proxy key,
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

#define MAX_EVENTS (10) // epoll
#define MAX_RETRY (30)  // nonblock 30*2ms
#define BACKLOG (5)     // 最大监听数
#define BUFSIZE (65536)
#define PORT2SERV (4321)
#define PORT2CLNT (4322)
#define nonBlockMode (1)
#define GET_2BYTE(buf) (((buf)[0] << 8) | (buf)[1])
#define GET_3BYTE(buf) (((buf)[0] << 16) | ((buf)[1] << 8) | (buf)[2])

const char *const pCAPath = "../ssl/ca/ca.crt";
const char *const certificate_path = "../ssl/ca/proxy.crt";
const char *const private_key_path = "../ssl/ca/proxy.key";

X509 *cert_proxy = NULL;
X509 *cert_server = NULL;
unsigned char random_server[SSL3_RANDOM_SIZE] = {0};
unsigned char random_client[SSL3_RANDOM_SIZE] = {0};
unsigned char master_secret[SSL3_MASTER_SECRET_SIZE] = {0};
unsigned char key_block[16 * 4] = {0};

void print_hex(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02X", buf[i]);
    }
}
void print_byte(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%s", buf[i]);
    }
}

void num_to_byte(size_t num, unsigned char *buffer, size_t buffer_length)
{
    for (int i = buffer_length - 1; i >= 0; i--)
    {
        buffer[i] = num & 0xFF; // 取最低8位
        num >>= 8;              // 向右移动8位
    }
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

static int tls12_PRF(const EVP_MD *md, unsigned char *out, size_t out_len,
                     const unsigned char *secret, size_t secret_len,
                     const unsigned char *label, size_t label_len,
                     const unsigned char *seed1, size_t seed1_len,
                     const unsigned char *seed2, size_t seed2_len,
                     const unsigned char *seed3, size_t seed3_len)
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

int cert_exchange(unsigned char *buf, size_t len, size_t len_left)
{
    unsigned char *bytes_cert_server = buf + 15;
    // len-=15;
    int len_cert_server = len - 15;
    cert_server = d2i_X509(NULL, &bytes_cert_server, len_cert_server);
    print_public_key(cert_server);
    // print_subject_info(cert_server);
    // 打印公钥和通用名
    print_public_key(cert_proxy);
    // print_subject_info(cert_proxy);

    // 获取证书的二进制比特流
    unsigned char *bytes_cert_proxy = NULL;
    int len_cert_proxy = i2d_X509(cert_proxy, &bytes_cert_proxy);
    if (len_cert_proxy > 0)
    {
        // print_hex(buf+15,len_cert_server);
        // copy to buf
        memmove(buf + 15 + len_cert_proxy, buf + 15 + len_cert_server,
                len_left + 1);
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

void prase_handshake(const unsigned char *buf, size_t len,
                     unsigned char *random_key)
{
    // handshake type
    buf += 5;
    unsigned char handshake_type = buf[0];
    // 解析协议版本（5-6 字节）
    // unsigned short protocol_version = (buf[4] << 8) + buf[5];
    // printf("Protocol Version: %04X\n", protocol_version);
    printf(" Protocol Version: ");
    print_hex(buf + 4, 2);
    printf("\n");

    // 解析随机数（7-38 字节）
    printf(" Random: ");
    // unsigned char *random_key=NULL;
    memmove(random_key, buf + 6, SSL3_RANDOM_SIZE);
    print_hex(random_key, SSL3_RANDOM_SIZE);

    printf("\n");

    // 解析会话 ID(39+)
    unsigned char session_id_length = buf[38];
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
        cipher_suites_length = (buf[38 + session_id_length + 1] << 8) +
                               buf[38 + session_id_length + 2];
        start_pos = 3;
    }
    // print_hex(buf+39,2);
    printf(" Cipher Suites: ");
    print_hex(buf + 38 + session_id_length + start_pos, cipher_suites_length);
    printf("\n");

    // 解析压缩算法
    unsigned char compression_methods_length =
        buf[38 + session_id_length + start_pos + cipher_suites_length];
    if (compression_methods_length > 0)
    {
        printf(" Compression Methods: ");
        print_hex(
            buf + 38 + session_id_length + start_pos + cipher_suites_length + 1,
            compression_methods_length);
        printf("\n");
    }
}

int get_keys(unsigned char *buf, size_t len, size_t len_left)
{
    unsigned char *preMaster_en = buf + 11;
    int len_preMaster_en = len - 11;
    RSA *rsa_prxyPriv = NULL; // 声明RSA结构体
    BIO *bio = NULL;          // 声明BIO结构体

    // 从文件中加载私钥
    bio = BIO_new_file(private_key_path, "rb");
    rsa_prxyPriv = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    unsigned char preMaster_de[SSL3_MASTER_SECRET_SIZE] = {0};
    int decryptedLength =
        RSA_private_decrypt(len_preMaster_en, preMaster_en, preMaster_de,
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
        print_hex(preMaster_de, SSL3_MASTER_SECRET_SIZE);
        printf("\n");
        const EVP_MD *md = EVP_sha256(); // 哈希函数

        unsigned char seed[SSL3_RANDOM_SIZE * 2]; // 两个随机数拼接
        memmove(seed, random_client, SSL3_RANDOM_SIZE);
        memmove(seed + SSL3_RANDOM_SIZE, random_server, SSL3_RANDOM_SIZE);

        // 计算PRF
        tls12_PRF(md, master_secret, SSL3_MASTER_SECRET_SIZE, preMaster_de,
                  SSL3_MASTER_SECRET_SIZE, TLS_MD_MASTER_SECRET_CONST,
                  TLS_MD_MASTER_SECRET_CONST_SIZE, random_client,
                  SSL3_RANDOM_SIZE, random_server, SSL3_RANDOM_SIZE, NULL, 0);
        tls12_PRF(md, key_block, sizeof(key_block), master_secret,
                  SSL3_MASTER_SECRET_SIZE, TLS_MD_KEY_EXPANSION_CONST,
                  TLS_MD_KEY_EXPANSION_CONST_SIZE, random_server,
                  SSL3_RANDOM_SIZE, random_client, SSL3_RANDOM_SIZE, NULL, 0);
        print_hex(master_secret, 48);
        printf("\n");
        print_hex(key_block, sizeof(key_block));
        printf("\n");
        // recrypt pms to server
        EVP_PKEY *pubKey = X509_get_pubkey(cert_server);
        RSA *rsa_servPub = EVP_PKEY_get1_RSA(pubKey);
        unsigned char *encryptedData[256];
        int encryptedLength =
            RSA_public_encrypt(SSL3_MASTER_SECRET_SIZE, preMaster_de,
                               encryptedData, rsa_servPub, RSA_PKCS1_PADDING);

        RSA_free(rsa_servPub);
        if (encryptedLength != len_preMaster_en)
        {
            memmove(buf + 11 + encryptedLength, buf + len, len_left);
        }
        memmove(buf + 11, encryptedData, encryptedLength);
        return encryptedLength - len_preMaster_en;
    }
}

int handleMsg(unsigned char *buf, size_t len)
{
#define MSG_HEAD_LEN 5
    unsigned char *p = NULL;
    size_t i = 0;
    unsigned char content_type = 0;
    unsigned short content_lenth = 0;
    int diff = 0;
    while (i < len)
    {
        i += content_lenth;
        p = buf + i;
        content_type = p[0];
        content_lenth = GET_2BYTE(p + 3) + MSG_HEAD_LEN;

        if (content_type == 22)
        { // Handshake message
            if (p[MSG_HEAD_LEN] == 0)
            { // Client Hello
                printf("Hello Request\n");
            }
            else if (p[MSG_HEAD_LEN] == 1)
            { // Client Hello
                printf("Received Client Hello:\n");
                prase_handshake(p, content_lenth - MSG_HEAD_LEN, random_client);
            }
            else if (p[MSG_HEAD_LEN] == 2)
            { // Server Hello
                printf("Received Server Hello:\n");
                prase_handshake(p, content_lenth - MSG_HEAD_LEN, random_server);
            }
            else if (p[MSG_HEAD_LEN] == 11)
            {
                printf("Received Certificate:\n");
                diff = cert_exchange(p, content_lenth, len - i - content_lenth);

                content_lenth += diff;
                len += diff;
            }
            else if (p[MSG_HEAD_LEN] == 12)
            {
                printf("Server Key Exchange:\n");
            }
            else if (p[MSG_HEAD_LEN] == 13)
            {
                printf("Certificate Request:\n");
            }
            else if (p[MSG_HEAD_LEN] == 14)
            {
                printf("Server Hello Done:\n");
            }
            else if (p[MSG_HEAD_LEN] == 15)
            {
                printf("Certificate Verify:\n");
            }
            else if (p[MSG_HEAD_LEN] == 16)
            {
                printf("Client Key Exchange:\n");
                diff = get_keys(p, content_lenth, len - i - content_lenth);

                content_lenth += diff;
                len += diff;
            }
            else if (p[MSG_HEAD_LEN] == 20)
            {
                printf("Finished\n");
                reMAC();
            }
        }
        else if (content_type == 20)
        {
            printf("ChangeCipherSpec\n");
        }
        else if (content_type == 21)
        {
            printf("Alert\n");
        }
        else if (content_type == 23)
        {
            printf("Application\n");
        }
    }
    // printf("\n");
    return len;
}

int trans(int sock_from, int sock_to, unsigned char *transBuf)
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
            // sprintf(sendBuf, BUFSIZE, "%s", recvBuf);
            // printf("\n%d ",recvBytes);
            totalTransBytes += recvBytes;
            recvBytes = handleMsg(transBuf, recvBytes);
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
                    printf("max retry, recv finished:%d %d\n", recvBytes,
                           errno);
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

int loadCertFile(const char *path)
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
    cert_proxy = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if (!cert_proxy)
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

    // int transBytes = 0;
    // int recvBytes = 0;
    // int sendBytes = 0;
    unsigned char *transBuf;
    transBuf = (unsigned char *)malloc(BUFSIZE * sizeof(char));
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
            loadCertFile(certificate_path) != 0)
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
            printf("%s(%d)Epoll creation failed:%d\n", __func__, __LINE__,
                   errno);
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
                printf("%s(%d)Epoll wait error:%d\n", __func__, __LINE__,
                       errno);
                continue;
            }
            for (int i = 0; i < epoll_ready; i++)
            {
                if (events[i].data.fd == proxySocket)
                {
                    // 有新的连接请求
                    proxyConn2Clnt = -1;
                    proxyConn2Clnt = accept(
                        proxySocket, (struct sockaddr *)&clntAddr, &addrSize);
                    if (proxyConn2Clnt < 0)
                    {
                        printf("%s(%d)Accept failed:%d\n", __func__, __LINE__,
                               errno);
                        continue;
                    }
                    else
                    {
                        printf("\nNew Client %d...\n", proxyConn2Clnt);
                    }
                    setsockopt(proxyConn2Clnt, SOL_SOCKET, SO_RCVTIMEO,
                               &timeout, sizeof(timeout)); // 超时返回-1

                    // 将客户端socket注册到epoll
                    event.events = EPOLLIN;
                    event.data.fd = proxyConn2Clnt;
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, proxyConn2Clnt,
                                  &event) == -1)
                    {
                        printf("%s(%d)Epoll control error:%d\n", __func__,
                               __LINE__, errno);
                        close(proxyConn2Clnt);
                        continue;
                    }
                }
                else
                {
                    proxySocket2Serv = -1;

                    do
                    {
                        if (socketInit2Serv(&proxySocket2Serv, ipBuf,
                                            &proxyAddr2Serv) != 0)
                        {
                            break;
                        }
                        setsockopt(proxySocket2Serv, SOL_SOCKET, SO_RCVTIMEO,
                                   &timeout, sizeof(timeout)); // 超时返回-1
                        if (connect(proxySocket2Serv,
                                    (struct sockaddr *)&proxyAddr2Serv,
                                    addrSize) < 0)
                        {
                            printf("%s(%d)Connect to server failed: %d\n",
                                   __func__, __LINE__, errno);
                            close(proxySocket2Serv);
                            break;
                        }
#if nonBlockMode
                        //
                        int nonBlockFlagsS =
                            fcntl(proxySocket2Serv, F_GETFL, 0);
                        int nonBlockFlagsC =
                            fcntl(events[i].data.fd, F_GETFL, 0);
#endif
                        // 有数据可读
                        while (1)
                        {
                            memset(transBuf, '\0', sizeof(transBuf));

                            int retryCount = 0;
                            int transBytes = 0;
                            int recvBytes = 0;
                            int sendBytes = 0;
                            recvBytes =
                                recv(events[i].data.fd, transBuf, BUFSIZE, 0);
                            if (recvBytes > 0)
                            {
                                retryCount = 0;
                                transBytes += recvBytes;
                                recvBytes = handleMsg(transBuf, recvBytes);
                                printf("%s", transBuf);
                                sendBytes = send(proxySocket2Serv, transBuf,
                                                 recvBytes, 0);
                                if (sendBytes < 0)
                                {
                                    printf("Send failed\n");
                                    break;
                                }
                            }
                            else if (recvBytes == 0)
                            {
                                // 客户端断开连接或出错
                                printf("Disconnected:%d %d\n", recvBytes,
                                       errno);
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
                                        printf("Max retry:%d %d\n", recvBytes,
                                               errno);
                                        break;
                                    }
                                    // continue;
                                }
                                printf("Connect error:%d %d\n", recvBytes,
                                       errno);
                                break;
                            }

#if nonBlockMode
                            fcntl(events[i].data.fd, F_SETFL,
                                  nonBlockFlagsC | O_NONBLOCK);
#endif
                            transBytes += trans(events[i].data.fd,
                                                proxySocket2Serv, transBuf);
                            printf("Recv:(%d)\n", transBytes);
#if nonBlockMode
                            fcntl(events[i].data.fd, F_SETFL,
                                  nonBlockFlagsC & ~O_NONBLOCK);
                            fcntl(proxySocket2Serv, F_SETFL,
                                  nonBlockFlagsS | O_NONBLOCK);
#endif
                            transBytes = 0;
                            transBytes += trans(proxySocket2Serv,
                                                events[i].data.fd, transBuf);
                            printf("Recv:(%d)\n", transBytes);
#if nonBlockMode
                            fcntl(proxySocket2Serv, F_SETFL,
                                  nonBlockFlagsS & ~O_NONBLOCK);
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
    X509_free(cert_proxy);
    X509_free(cert_server);
    return 0;
}