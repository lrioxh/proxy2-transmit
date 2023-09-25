// TODO
// epoll -o
// ssl  -o
// test nonblock with waiting event
// clean code
// 会话缓存（Session Cache）?
// all send still in block mode

// sudo apt install libssl-dev
// sudo tcpdump -iany tcp port 4322

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/unistd.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_EVENTS (10) // epoll
#define MAX_RETRY (30)  // nonblock 30*2ms
#define BACKLOG (5)     // 最大监听数
#define BUFSIZE (65536)
#define PORT2SERV (4321)
#define PORT2CLNT (4323)
#define nonBlockMode (1)
#define VIRIFY_SERVER_CA (1)

const char *const pCAPath = "../ssl/ca/ca.crt";
const char *const certificate_path = "../ssl/ca/proxy.crt";
const char *const private_key_path = "../ssl/ca/proxy.key";

void SSL_info_callback(const SSL *ssl, int where, int ret)
{
    if (where & SSL_CB_HANDSHAKE_START)
    {
        printf("SSL handshake started\n");
    }

    if (where & SSL_CB_HANDSHAKE_DONE)
    {
        printf("SSL handshake done\n");
    }

    if (where & SSL_CB_READ)
    {
        printf("SSL READ\n");
        // char buf[4096];
        // int len = SSL_read((SSL *)ssl, buf, sizeof(buf));
        // if (len > 0) {
        //     // 在这里可以检查是否为 Client Hello 或 Server Hello 报文
        //     // 对于更复杂的检查可能需要额外的逻辑
        //     printf("Received %d bytes\n", len);
        // }
    }
}
void print_hex(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02X", buf[i]);
    }
}

void print_tls_handshake_info(const unsigned char *buf, size_t len)
{
    // handshake type
    unsigned char handshake_type = buf[0];
    // 解析协议版本（5-6 字节）
    // unsigned short protocol_version = (buf[4] << 8) + buf[5];
    // printf("Protocol Version: %04X\n", protocol_version);
    printf(" Protocol Version: ");
    print_hex(buf + 4, 2);
    printf("\n");

    // 解析随机数（7-38 字节）
    printf(" Random: ");
    print_hex(buf + 6, 32);
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
        // printf("%d %d",(buf[38 + session_id_length + 1] << 8),buf[38 + session_id_length + 2]);
        cipher_suites_length = (buf[38 + session_id_length + 1] << 8) + buf[38 + session_id_length + 2];
        start_pos = 3;
    }
    // print_hex(buf+39,2);
    printf(" Cipher Suites: ");
    print_hex(buf + 38 + session_id_length + start_pos, cipher_suites_length);
    printf("\n");

    // 解析压缩算法
    unsigned char compression_methods_length = buf[38 + session_id_length + start_pos + cipher_suites_length];
    if (compression_methods_length > 0)
    {
        printf(" Compression Methods: ");
        print_hex(buf + 38 + session_id_length + start_pos + cipher_suites_length + 1, compression_methods_length);
        printf("\n");
    }
}

void SSL_msg_callback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
    if (content_type == 22)
    { // Handshake message
        const unsigned char *p = buf;
        if (p[0] == 0)
        { // Client Hello
            printf("Hello Request\n");
            // print_tls_handshake_info(p, len);
        }
        else if (p[0] == 1)
        { // Client Hello
            printf("Received Client Hello:\n");
            print_tls_handshake_info(p, len);
        }
        else if (p[0] == 2)
        { // Server Hello
            printf("Received Server Hello:\n");
            print_tls_handshake_info(p, len);
        }
        else if (p[0] == 11)
        {
            printf("Received Certificate:\n");
            // print_tls_handshake_info(p, len);
        }
        else if (p[0] == 12)
        {
            printf("Server Key Exchange:\n");
            // print_tls_handshake_info(p, len);
        }
        else if (p[0] == 13)
        {
            printf("Certificate Request:\n");
            // print_tls_handshake_info(p, len);
        }
        else if (p[0] == 14)
        {
            printf("Server Hello Done:\n");
            // print_tls_handshake_info(p, len);
        }
        else if (p[0] == 135)
        {
            printf("Certificate Verify:\n");
            // print_tls_handshake_info(p, len);
        }
        else if (p[0] == 16)
        {
            printf("Client Key Exchange:\n");
            // print_tls_handshake_info(p, len);
        }
        else if (p[0] == 20)
        {
            printf("Finished\n");
            // print_tls_handshake_info(p, len);
        }
    }
    else if (content_type == 20)
    {
        printf("ChangeCipherSpec\n");
    }
    else if (content_type == 23)
    {
        printf("Application\n");
    }
}

int SSL_CTX_INIT_C2S(SSL_CTX **pCtx2Serv, const SSL_METHOD *pMethod, long timeout)
{
    /*ssl 2 serv*/
    *pCtx2Serv = SSL_CTX_new(pMethod);
    SSL_CTX_set_timeout(*pCtx2Serv, timeout);
    SSL_CTX_set_info_callback(*pCtx2Serv, SSL_info_callback);
    SSL_CTX_set_msg_callback(*pCtx2Serv, SSL_msg_callback);
#if VIRIFY_SERVER_CA
    /*加载CA证书（对端证书需要用CA证书来验证）*/
    if (SSL_CTX_load_verify_locations(*pCtx2Serv, pCAPath, NULL) != 1)
    {
        printf("%s %d error=%d\n", __func__, __LINE__, errno);
        return errno;
    }

    /*设置对端证书验证*/
    SSL_CTX_set_verify(*pCtx2Serv, SSL_VERIFY_PEER, NULL);
#endif
    return 0;
}

int SSL_CTX_INIT_S2C(SSL_CTX **pCtx2Clnt, const SSL_METHOD *pMethod, long timeout)
{
    /*初始化SSL上下文环境变量函数*/
    *pCtx2Clnt = SSL_CTX_new(pMethod);
    SSL_CTX_set_timeout(*pCtx2Clnt, timeout);
    SSL_CTX_set_info_callback(*pCtx2Clnt, SSL_info_callback);
    SSL_CTX_set_msg_callback(*pCtx2Clnt, SSL_msg_callback);

    if (NULL == *pCtx2Clnt)
    {
        printf("%s %d error=%d\n", __func__, __LINE__, errno);
        return errno;
    }

    /*ssl 2 clnt*/
    /* 载入数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
    if (SSL_CTX_use_certificate_file(*pCtx2Clnt, certificate_path, SSL_FILETYPE_PEM) <= 0)
    {
        printf("%s %d error=%d\n", __func__, __LINE__, errno);
        return errno;
    }
    /* 载入私钥 */
    if (SSL_CTX_use_PrivateKey_file(*pCtx2Clnt, private_key_path, SSL_FILETYPE_PEM) <= 0)
    {
        printf("%s %d error=%d\n", __func__, __LINE__, errno);
        return errno;
    }

    /* 检查私钥是否正确 */
    if (SSL_CTX_check_private_key(*pCtx2Clnt) <= 0)
    {
        printf("%s %d error=%d\n", __func__, __LINE__, errno);
        return errno;
    }

    /*证书验证*/
    SSL_CTX_set_verify(*pCtx2Clnt, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_options(*pCtx2Clnt, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_mode(*pCtx2Clnt, SSL_MODE_AUTO_RETRY);
    return 0;
}

int SSL_INIT(SSL **pSSL, SSL_CTX *pCtx, int socket, int timeout)
{
    /*基于pCtx产生一个新的ssl*/
    *pSSL = SSL_new(pCtx);
    if (NULL == *pSSL)
    {
        printf("%s %d error=%d\n", __func__, __LINE__, errno);
        return errno;
    }
    /*将连接的socket加入到ssl*/
    SSL_set_fd(*pSSL, socket);
    // 控制 SSL/TLS 连接在阻塞模式下的行为
    SSL_set_mode(*pSSL, SSL_MODE_AUTO_RETRY);
    SSL_SESSION *session = SSL_get_session(*pSSL);
    SSL_set_timeout(session, timeout);

    return 0;
}

int certVerify(SSL *pSSL)
{
    X509 *pX509Cert = NULL;
    X509_NAME *pX509Subject = NULL;
    char szBuf[256] = {0};
    char szSubject[1024] = {0};
    char szIssuer[256] = {0};
    /*获取验证对端证书的结果*/
    int iRet = -1;
    if (iRet = SSL_get_verify_result(pSSL) != X509_V_OK)
    {
        printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(ERR_get_error(), NULL));
        return errno;
    }

    /*获取对端证书*/
    pX509Cert = SSL_get_peer_certificate(pSSL);

    if (NULL == pX509Cert)
    {
        printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(ERR_get_error(), NULL));
        return errno;
    }

    /*获取证书使用者属性*/
    pX509Subject = X509_get_subject_name(pX509Cert);
    if (NULL == pX509Subject)
    {
        printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(SSL_get_error(pSSL, iRet), NULL));
        return errno;
    }
    X509_NAME_oneline(pX509Subject, szSubject, sizeof(szSubject) - 1);
    X509_NAME_oneline(X509_get_issuer_name(pX509Cert), szIssuer, sizeof(szIssuer) - 1);
    X509_NAME_get_text_by_NID(pX509Subject, NID_commonName, szBuf, sizeof(szBuf) - 1);
    printf("szSubject =%s \nszIssuer =%s\n  commonName =%s\n", szSubject, szIssuer, szBuf);
    if (pX509Cert)
    {
        X509_free(pX509Cert);
    }
    return 0;
}

void parse_tls_handshake(SSL *ssl)
{
    SSL_SESSION *session = SSL_get_session(ssl);

    if (session)
    {
        printf("Protocol Version: %s\n", SSL_get_version(ssl));
        printf("Cipher Suite: %s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
        // printf("Session ID: ");
        // for (int i = 0; i < session->session_id_length; i++) {
        //     printf("%02X", session->session_id[i]);
        // }
        // printf("\n");
    }
}

int handleMsg(unsigned char *buf)
{
    // unsigned char msg_type = buf[0];
    // if (msg_type == 0x16)
    // { // Handshake message
    //     unsigned char handshake_type = buf[5];

    //     if (handshake_type == 0x01)
    //     { // Client Hello
    //         printf("Received Client Hello:\n");
    //         // 解析Client Hello报文，输出所需字段
    //         // 例如：版本号、随机数、会话ID等
    //     }
    //     else if (handshake_type == 0x02)
    //     { // Server Hello
    //         printf("Received Server Hello:\n");
    //         // 解析Server Hello报文，输出所需字段
    //         // 例如：版本号、随机数等
    //     }
    // }
    // else
    // {
    //     // printf("Received %s\n",buf);
    // }
}

int SSL_Trans(SSL *pSSL_from, SSL *pSSL_to, char *transBuf)
{
    int recvBytes = 0;
    int totalTransBytes = 0;
    int retryCount = 0;
    int errn = 0;
    int sendBytes = 0;
    parse_tls_handshake(pSSL_from);
    while (1)
    {
        recvBytes = SSL_read(pSSL_from, transBuf, BUFSIZE);
        if (recvBytes > 0)
        {
            retryCount = 0;
            // sprintf(sendBuf, BUFSIZE, "%s", recvBuf);
            // printf("\n%d ",recvBytes);
            handleMsg(transBuf);
            totalTransBytes += recvBytes;
            // send here
            sendBytes = SSL_write(pSSL_to, transBuf, recvBytes);
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
            errn = SSL_get_error(pSSL_from, recvBytes);
            if (errn == SSL_ERROR_WANT_READ || errn == SSL_ERROR_WANT_WRITE)
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

    /*SSL库初始化（一个进程只初始化一次）*/
    SSL_library_init();
    /*载入所有ssl错误消息*/
    SSL_load_error_strings();
    /*载入所有ssl算法*/
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *pMethod = TLSv1_2_method();
    SSL_CTX *pCtx2Serv = NULL;
    SSL_CTX *pCtx2Clnt = NULL;
    SSL *pSSL2Serv = NULL;
    SSL *pSSL2Clnt = NULL;

    int proxySocket = -1;
    struct sockaddr_in proxyAddr = {0};
    socklen_t addrSize = sizeof(struct sockaddr);
    int proxyConn2Clnt = -1;
    struct sockaddr_in clntAddr = {0};
    int proxySocket2Serv = -1;
    struct sockaddr_in proxyAddr2Serv = {0};

    int transBytes = 0;
    int recvBytes = 0;
    int sendBytes = 0;
    unsigned char *transBuf;
    transBuf = (unsigned char *)malloc(BUFSIZE * sizeof(char));
    char ipBuf[16] = "192.168.137.1";
    // char ipBuf[16] = "127.0.0.1";

    struct timeval timeout;
    timeout.tv_sec = 1; // 设置超时为1秒
    timeout.tv_usec = 0;

    int iRet = -1;
    int epoll_fd = -1;
    int epoll_ready = 0;
    struct epoll_event event, events[MAX_EVENTS];

    do
    {
        /*初始化SSL上下文环境变量函数*/
        if (SSL_CTX_INIT_S2C(&pCtx2Clnt, pMethod, timeout.tv_sec) != 0)
        {
            break;
        }
        /*ssl 2 serv*/
        if (SSL_CTX_INIT_C2S(&pCtx2Serv, pMethod, timeout.tv_sec) != 0)
        {
            break;
        }
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
        // deal with different connection
        // maybe new thread
        while (1)
        {
            //-1: waiting forever(ms)
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
                    //
                    setsockopt(proxyConn2Clnt, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)); // 超时返回-1

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
                    // as client to server
                    proxySocket2Serv = -1;

                    {
                        if (socketInit2Serv(&proxySocket2Serv, ipBuf, &proxyAddr2Serv) != 0)
                        {
                            break;
                        }
                        setsockopt(proxySocket2Serv, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)); // 超时返回-1
                        if (
                            connect(proxySocket2Serv, (struct sockaddr *)&proxyAddr2Serv, addrSize) < 0)
                        {
                            printf("%s(%d)Connect to server failed: %d\n", __func__, __LINE__, errno);
                            break;
                        }
                        if (SSL_INIT(&pSSL2Clnt, pCtx2Clnt, events[i].data.fd, timeout.tv_sec) != 0)
                        {
                            break;
                        }

                        if (SSL_INIT(&pSSL2Serv, pCtx2Serv, proxySocket2Serv, timeout.tv_sec) != 0)
                        {
                            break;
                        }
                        /*建立ssl连接（握手）*/
                        iRet = SSL_accept(pSSL2Clnt);
                        if (iRet < 0)
                        {
                            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                                   ERR_error_string(SSL_get_error(pSSL2Clnt, iRet), NULL));
                            break;
                        }
                        /*ssl握手*/
                        iRet = SSL_connect(pSSL2Serv);
                        if (iRet < 0)
                        {
                            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                                   ERR_error_string(SSL_get_error(pSSL2Serv, iRet), NULL));
                            break;
                        }
#if nonBlockMode
                        //
                        int nonBlockFlagsS = fcntl(proxySocket2Serv, F_GETFL, 0);
                        int nonBlockFlagsC = fcntl(events[i].data.fd, F_GETFL, 0);
#endif

#if VIRIFY_SERVER_CA
                        if (certVerify(pSSL2Serv) != 0)
                        {
                            break;
                        }
#endif
                        // 有数据可读
                        while (1)
                        {
                            memset(transBuf, '\0', sizeof(transBuf));
                            int errn = 0;
                            int retryCount = 0;
                            transBytes = 0;
                            // transBytes += recv(events[i].data.fd, transBuf, BUFSIZE,0);
                            // printf("\n%s",transBuf);
                            transBytes += SSL_read(pSSL2Clnt, transBuf, BUFSIZE);
                            if (transBytes > 0)
                            {
                                // printf("from clent: (%d)\n", transBytes);
                                handleMsg(transBuf);
                                sendBytes = SSL_write(pSSL2Serv, transBuf, transBytes);
                                if (sendBytes < 0)
                                {
                                    printf("Send failed\n");
                                    break;
                                }
                            }
                            else if (transBytes == 0)
                            {
                                // 客户端断开连接或出错
                                printf("Disconnected:%d %d\n", transBytes, errno);
                                break;
                            }
                            else
                            {
                                errn = SSL_get_error(pSSL2Clnt, recvBytes);
                                if (errn == SSL_ERROR_WANT_READ || errn == SSL_ERROR_WANT_WRITE)
                                {
                                    if (retryCount < MAX_RETRY)
                                    {
                                        retryCount++;
                                        continue;
                                    }
                                    else
                                    {

                                        printf("Max retry:%d %d\n", transBytes, errno);
                                        break;
                                    }
                                    // continue;
                                }
                                printf("Connect error:%d %d\n", transBytes, errno);
                                break;
                            }

#if nonBlockMode
                            fcntl(events[i].data.fd, F_SETFL, nonBlockFlagsC | O_NONBLOCK);
#endif
                            transBytes += SSL_Trans(pSSL2Clnt, pSSL2Serv, transBuf);
                            printf("Recv:(%d)\n", transBytes);
#if nonBlockMode
                            fcntl(events[i].data.fd, F_SETFL, nonBlockFlagsC & ~O_NONBLOCK);
                            fcntl(proxySocket2Serv, F_SETFL, nonBlockFlagsS | O_NONBLOCK);
#endif
                            transBytes = 0;
                            transBytes += SSL_Trans(pSSL2Serv, pSSL2Clnt, transBuf);
                            printf("Recv:(%d)\n", transBytes);
#if nonBlockMode
                            fcntl(proxySocket2Serv, F_SETFL, nonBlockFlagsS & ~O_NONBLOCK);
#endif
                        }
                    }
                    while (0)
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                    if (events[i].data.fd > 0)
                    {
                        close(events[i].data.fd);
                    }
                }
            }
        }
    } while (0);

    if (pSSL2Serv)
    {
        SSL_free(pSSL2Serv);
        pSSL2Serv = NULL;
    }
    if (pSSL2Clnt)
    {
        SSL_free(pSSL2Clnt);
        pSSL2Clnt = NULL;
    }
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
    EVP_cleanup();
    return 0;
}