// TODO
// epoll -o
// ssl  -o
// test nonblock with waiting event

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
// #include <openssl/bio.h>
#include <openssl/err.h>

#define MAX_EVENTS (10) // epoll
#define BACKLOG (5)     // 最大监听数
#define BUFSIZE (102400)
#define PORT2SERV (4321)
#define PORT2CLNT (4322)
#define nonBlockMode (1)
#define VIRIFY_SERVER_CA (1)

const char *const pCAPath = "../ssl/ca/ca.crt";
const char *const certificate_path = "../ssl/ca/proxy.crt";
const char *const private_key_path = "../ssl/ca/proxy.key";
// const char *const password = "123456";

// int main(int argc, char *argv[]) {
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
    SSL* pSSL2Serv = NULL;
    SSL* pSSL2Clnt = NULL;

    int iRet = -1;
    X509* pX509Cert = NULL;
    X509_NAME* pX509Subject = NULL;

    int proxySocket = -1;
    struct sockaddr_in proxyAddr = {0};
    socklen_t addrSize = sizeof(struct sockaddr);
    int proxyConn2Clnt = -1;
    struct sockaddr_in clntAddr = {0};
    int proxySocket2Serv = -1;
    struct sockaddr_in proxyAddr2Serv = {0};

    int recvBytes = 0;
    int sendBytes = 0;
    char* transBuf;
    transBuf = (char*)malloc(BUFSIZE*sizeof(char));
    char ipBuf[16] = "192.168.137.1";

    int nonBlockFlags = 0;
    struct timeval timeout;
    timeout.tv_sec = 5; // 设置超时为5秒
    timeout.tv_usec = 0;

    int epoll_fd = -1;
    int epoll_ready=0;
    struct epoll_event event, events[MAX_EVENTS];

    // as a server
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_addr.s_addr = htonl(INADDR_ANY); // ip地址
    proxyAddr.sin_port = htons(PORT2CLNT);         // 绑定端口

    char szBuf[256] = {0};
    char szSubject[1024] = {0};
    char szIssuer[256] = {0};

    do
    {
        /*初始化SSL上下文环境变量函数*/
        pCtx2Clnt = SSL_CTX_new(pMethod);
        SSL_CTX_set_timeout(pCtx2Clnt, timeout.tv_sec);

        if (NULL == pCtx2Clnt)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }

        /*ssl 2 clnt*/
        /* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
        if (SSL_CTX_use_certificate_file(pCtx2Clnt, certificate_path, SSL_FILETYPE_PEM) <= 0)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }
// #if 1
//         /*设置私钥的解锁密码*/
//         SSL_CTX_set_default_passwd_cb_userdata(pCtx2Clnt, password);
// #endif
        /* 载入用户私钥 */
        if (SSL_CTX_use_PrivateKey_file(pCtx2Clnt, private_key_path, SSL_FILETYPE_PEM) <= 0)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }

        /* 检查用户私钥是否正确 */
        if (SSL_CTX_check_private_key(pCtx2Clnt) <= 0)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }

        /*证书验证*/
        SSL_CTX_set_verify(pCtx2Clnt, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_options(pCtx2Clnt, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        SSL_CTX_set_mode(pCtx2Clnt, SSL_MODE_AUTO_RETRY);

        /*ssl 2 serv*/
        pCtx2Serv = SSL_CTX_new(pMethod);
        SSL_CTX_set_timeout(pCtx2Serv, timeout.tv_sec);
#if VIRIFY_SERVER_CA
        /*加载CA证书（对端证书需要用CA证书来验证）*/
        if (SSL_CTX_load_verify_locations(pCtx2Serv, pCAPath, NULL) != 1)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }

        /*设置对端证书验证*/
        SSL_CTX_set_verify(pCtx2Serv, SSL_VERIFY_PEER, NULL);
#endif

        proxySocket = socket(AF_INET, SOCK_STREAM, 0);
        if (proxySocket < 0)
        {
            printf("%s(%d)Socket error:%d\n", __func__, __LINE__, errno);
            break;
        }
        if (bind(proxySocket, (struct sockaddr *)&proxyAddr, addrSize) < 0)
        {
            printf("%s(%d)Failed bind:%d\n", __func__, __LINE__, errno);
            break;
        }
        if (listen(proxySocket, BACKLOG) < 0)
        {
            printf("%s(%d)Listen failed:%d\n", __func__, __LINE__, errno);
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
                    // struct sockaddr_in clntAddr = {0};
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
                    setsockopt(proxyConn2Clnt, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)); // 超时返回-1
                    nonBlockFlags = fcntl(proxyConn2Clnt, F_GETFL, 0);

                    // 将客户端socket注册到epoll
                    event.events = EPOLLIN;
                    event.data.fd = proxyConn2Clnt;
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, proxyConn2Clnt, &event) == -1)
                    {
                        printf("%s(%d)Epoll control error:%d\n", __func__, __LINE__, errno);
                        // SSL_shutdown(pSSL2Clnt);
                        close(proxyConn2Clnt);
                        continue;
                    }
                }
                else
                {
                    // as client to server
                    proxySocket2Serv = -1;
                    // int iRet = -1;
                    // struct sockaddr_in proxyAddr2Serv = {0};
                    // SSL *pSSL2Clnt = NULL;
                    // SSL *pSSL2Serv = NULL;
                    // X509 *pX509Cert = NULL;
                    // X509_NAME *pX509Subject = NULL;

                    inet_pton(AF_INET, ipBuf, &proxyAddr2Serv.sin_addr.s_addr);
                    // proxyAddr2Serv.sin_addr.s_addr = clntAddr.sin_addr.s_addr;
                    proxyAddr2Serv.sin_family = AF_INET;
                    proxyAddr2Serv.sin_port = htons(PORT2SERV);

                    do
                    {
                        proxySocket2Serv = socket(AF_INET, SOCK_STREAM, 0);
                        if (proxySocket2Serv < 0)
                        {
                            printf("%s(%d)Client socket error: %d\n", __func__, __LINE__, errno);
                            break;
                        }
                        setsockopt(proxySocket2Serv, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)); // 超时返回-1
                        if (
                            connect(proxySocket2Serv, (struct sockaddr *)&proxyAddr2Serv, addrSize) < 0)
                        {
                            printf("%s(%d)Connect to server failed: %d\n", __func__, __LINE__, errno);
                            // close(proxySocket2Serv);
                            break;
                        }
                        /*基于pCtx产生一个新的ssl*/
                        pSSL2Clnt = SSL_new(pCtx2Clnt);
                        if (NULL == pSSL2Clnt)
                        {
                            printf("%s %d error=%d\n", __func__, __LINE__, errno);
                            // close(proxySocket2Serv);
                            break;
                        }
                        /*将连接的socket加入到ssl*/
                        SSL_set_fd(pSSL2Clnt, events[i].data.fd);

                        /*建立ssl连接（握手）*/
                        iRet = SSL_accept(pSSL2Clnt);
                        if (iRet < 0)
                        {
                            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(SSL_get_error(pSSL2Clnt, iRet), NULL));
                            // close(proxySocket2Serv);
                            break;
                        }
                        /*基于pCtx产生一个新的ssl*/
                        pSSL2Serv = SSL_new(pCtx2Serv);
                        if (NULL == pSSL2Serv)
                        {
                            printf("%s %d error=%d\n", __func__, __LINE__, errno);
                            // close(proxySocket2Serv);
                            break;
                        }
                        /*将连接的socket加入到ssl*/
                        SSL_set_fd(pSSL2Serv, proxySocket2Serv);

                        /*ssl握手*/
                        iRet = SSL_connect(pSSL2Serv);
                        if (iRet < 0)
                        {
                            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(SSL_get_error(pSSL2Serv, iRet), NULL));
                            // SSL_shutdown(pSSL2Serv);
                            // close(proxySocket2Serv);
                            break;
                        }
#if VIRIFY_SERVER_CA
                        /*获取验证对端证书的结果*/
                        if (X509_V_OK != SSL_get_verify_result(pSSL2Serv))
                        {
                            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(ERR_get_error(), NULL));
                            // SSL_shutdown(pSSL2Serv);
                            // close(proxySocket2Serv);
                            break;
                        }

                        /*获取对端证书*/
                        pX509Cert = SSL_get_peer_certificate(pSSL2Serv);

                        if (NULL == pX509Cert)
                        {
                            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(ERR_get_error(), NULL));
                            // SSL_shutdown(pSSL2Serv);
                            // close(proxySocket2Serv);
                            break;
                        }

                        /*获取证书使用者属性*/
                        pX509Subject = X509_get_subject_name(pX509Cert);
                        if (NULL == pX509Subject)
                        {
                            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(SSL_get_error(pSSL2Serv, iRet), NULL));
                            // SSL_shutdown(pSSL2Serv);
                            // close(proxySocket2Serv);
                            break;
                        }
                        // char szBuf[256] = {0};
                        // char szSubject[1024] = {0};
                        // char szIssuer[256] = {0};
                        X509_NAME_oneline(pX509Subject, szSubject, sizeof(szSubject) - 1);
                        X509_NAME_oneline(X509_get_issuer_name(pX509Cert), szIssuer, sizeof(szIssuer) - 1);
                        X509_NAME_get_text_by_NID(pX509Subject, NID_commonName, szBuf, sizeof(szBuf) - 1);
                        printf("szSubject =%s \nszIssuer =%s\n  commonName =%s\n", szSubject, szIssuer, szBuf);
#endif
                        // 有数据可读
                        // int recvBytes = 0, sendBytes = 0;
                        // char *transBuf;
                        // transBuf = (char *)malloc(BUFSIZE * sizeof(char));
                        while (1)
                        {
                            memset(transBuf, '\0', sizeof(transBuf));

                            // recvBytes = recv(events[i].data.fd, transBuf, BUFSIZE, 0);
                            recvBytes = SSL_read(pSSL2Clnt, transBuf, BUFSIZE);
                            if (recvBytes > 0)
                            {
                                printf("from clent: (%d)\n", recvBytes);
                                // sprintf(sendBuf, BUFSIZE, "%s", recvBuf);
                                sendBytes = SSL_write(pSSL2Serv, transBuf, recvBytes);
                                if (sendBytes < 0)
                                {
                                    printf("send to server failed\n");
                                    break;
                                }
                            }
                            else if (recvBytes == 0)
                            {
                                // 客户端断开连接或出错，从epoll中移除
                                // epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                                // close(events[i].data.fd);
                                printf("Client disconnected:%d %d\n", recvBytes, errno);
                                break;
                            }
                            else
                            {
                                printf("Client connect error:%d %d\n", recvBytes, errno);
                                break;
                            }
#if nonBlockMode
                            fcntl(events[i].data.fd, F_SETFL, nonBlockFlags | O_NONBLOCK);
                            SSL_set_mode(pSSL2Clnt, SSL_MODE_AUTO_RETRY);
#endif
                            while (1)
                            {
                                // from client
                                //  recvBytes = recv(events[i].data.fd, transBuf, BUFSIZE, 0);
                                recvBytes = SSL_read(pSSL2Clnt, transBuf, BUFSIZE);
                                if (recvBytes > 0)
                                {
                                    printf("from clent: (%d)\n", recvBytes);
                                    // sprintf(sendBuf, BUFSIZE, "%s", recvBuf);
                                    // send here
                                    sendBytes = SSL_write(pSSL2Serv, transBuf, recvBytes);
                                    if (sendBytes < 0)
                                    {
                                        printf("send to server failed\n");
                                        break;
                                    }
                                }
                                else if (recvBytes == 0)
                                {
                                    printf("receive from clent finished:%d %d\n", recvBytes, errno);
                                    break;
                                }
                                else
                                {
                                    int errn = SSL_get_error(pSSL2Clnt, recvBytes);
                                    if (errn == SSL_ERROR_WANT_READ || errn == SSL_ERROR_WANT_WRITE)
                                    {
                                        // continue;
                                        // should bind wait event
                                        printf("receive from clent finished:%d %d\n", recvBytes, errno);
                                        break;
                                    }
                                    else
                                    {
                                        // 处理接收错误
                                        printf("%s %d recv from clnt error=%d\n", __func__, __LINE__, errno);
                                        break;
                                    }
                                }
                            }
#if nonBlockMode
                            fcntl(events[i].data.fd, F_SETFL, nonBlockFlags & ~O_NONBLOCK);
                            SSL_clear_mode(pSSL2Clnt, SSL_MODE_AUTO_RETRY);

#endif
                            while (1)
                            {
                                // from server
                                //  recvBytes = recv(proxySocket2Serv, transBuf, BUFSIZE, 0);
                                recvBytes = SSL_read(pSSL2Serv, transBuf, BUFSIZE);
                                if (recvBytes > 0)
                                {
                                    printf("from server: (%d)\n", recvBytes);
                                    // sprintf(sendBuf, BUFSIZE, "%s", recvBuf);
                                    sendBytes = SSL_write(pSSL2Clnt, transBuf, recvBytes);
                                    if (sendBytes < 0)
                                    {
                                        printf("send to client failed\n");
                                        break;
                                    }
                                }
                                else if (recvBytes == 0)
                                {
                                    printf("receive from serv finished:%d %d\n", recvBytes, errno);
                                    break;
                                }
                                else
                                {
                                    int errn = SSL_get_error(pSSL2Serv, recvBytes);
                                    if (errn == SSL_ERROR_WANT_READ || errn == SSL_ERROR_WANT_WRITE)
                                    {
                                        continue;
                                    }
                                    else
                                    {
                                        // 处理接收错误
                                        printf("%s %d recv from serv error=%d\n", __func__, __LINE__, errno);
                                        break;
                                    }
                                }
                            }
                            // if (recvBytes == 0)
                            // {
                            //     printf("Client disconnected:%d %d\n", recvBytes, errno);
                            //     break;
                            // }
                        }
                        // free(transBuf);
                    } while (0);

// #if VIRIFY_SERVER_CA

//                     if (pX509Cert)
//                     {
//                         X509_free(pX509Cert);
//                     }
// #endif
//                     if (pSSL2Serv)
//                     {
//                         SSL_free(pSSL2Serv);
//                         pSSL2Serv = NULL;
//                     }
                    // if (proxySocket2Serv > 0)
                    // {
                    //     close(proxySocket2Serv);
                    // }

                    // if (pSSL2Clnt)
                    // {
                    //     SSL_free(pSSL2Clnt);
                    //     pSSL2Clnt = NULL;
                    // }
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                    if (events[i].data.fd > 0)
                    {
                        close(events[i].data.fd);
                    }
                }
            }
        }

    } while (0);

#if VIRIFY_SERVER_CA

    if (pX509Cert)
    {
        X509_free(pX509Cert);
    }
#endif
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

    if (proxyConn2Clnt > 0) {
        close(proxyConn2Clnt);
    }
    if (proxySocket > 0)
    {
        close(proxySocket);
    }
    if (proxySocket2Serv > 0) {
        close(proxySocket2Serv);
    }
    free(transBuf);
    return 0;
}