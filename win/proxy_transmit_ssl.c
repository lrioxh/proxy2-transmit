
//TODO:0.文件传输 √
// 1.函数包装？ 合法值验证
// 2.多线程？epoll(linux)
// 3.上传（c2s）循环阻塞在recv无法退出 链接设置非阻塞模式√超时break√
// 4.openssl
// 5.缓冲区队列?
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")


//const int BUFSIZE = 100;
#define BACKLOG                 (5)	//最大监听数
#define BUFSIZE                 (102400)
#define PORT2SERV               (4321)
#define PORT2CLNT               (4322)
#define nonBlockMode            (1)
#define VIRIFY_SERVER_CA        (1)

//const char* const sIP = "127.0.0.1";
const char* const pCAPath = "../ssl/ca/ca.crt";
const char* const certificate_path = "../ssl/ca/proxy.crt";
const char* const private_key_path = "../ssl/ca/proxy.key";
const char* const password = "123456";

int main()
{
    /*SSL库初始化（一个进程只初始化一次）*/
    SSL_library_init();
    /*载入所有ssl错误消息*/
    SSL_load_error_strings();
    /*载入所有ssl算法*/
    OpenSSL_add_all_algorithms();

    const SSL_METHOD* pMethod = TLSv1_2_method();
    SSL_CTX* pCtx2Serv = NULL;
    SSL_CTX* pCtx2Clnt = NULL;
    SSL* pSSL2Serv = NULL;
    SSL* pSSL2Clnt = NULL;

    int iRet = -1;
    X509* pX509Cert = NULL;
    X509_NAME* pX509Subject = NULL;

    WSADATA wsaData;
    int wsaStarted = WSAStartup(MAKEWORD(2, 2), &wsaData); //目前建议使用最新2.2版本
    SOCKET proxySocket = -1;
    SOCKET proxyConn2Clnt = -1;
    SOCKET proxySocket2Serv = -1;
    struct sockaddr_in proxyAddr = { 0 };
    struct sockaddr_in proxyAddr2Serv = { 0 };
    struct sockaddr_in clntAddr = { 0 };
    int addrSize = sizeof(struct sockaddr);
    //int recvByte = 0;
    //int iSend = 0;
    //char* transBuf;
    //transBuf = (char*)malloc(BUFSIZE*sizeof(char));
    char ipBuf[16] = "127.0.0.1";

    unsigned long nonBlockingMode = 1;
    unsigned long blockingMode = 0;
    struct timeval timeout;
    timeout.tv_sec = 5;  // 设置超时为5秒
    timeout.tv_usec = 0;


    //as a server
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);//ip地址
    proxyAddr.sin_port = htons(PORT2CLNT);//绑定端口

    do {
        /*初始化SSL上下文环境变量函数*/
        pCtx2Clnt = SSL_CTX_new(pMethod);

        if (NULL == pCtx2Clnt)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }

        /* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
        if (SSL_CTX_use_certificate_file(pCtx2Clnt, certificate_path, SSL_FILETYPE_PEM) <= 0)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }
#if 1		
        /*设置私钥的解锁密码*/
        SSL_CTX_set_default_passwd_cb_userdata(pCtx2Clnt, password);
#endif
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

        pCtx2Serv = SSL_CTX_new(pMethod);
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
#if 0
        if (!SSL_CTX_set_cipher_list(pCtx2Serv, "ALL"))
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;

        }
#endif

        if (wsaStarted == 0) {
            proxySocket = socket(AF_INET, SOCK_STREAM, 0);//协议族，Socket类型，创建了可识别套接字
            //socke 返回类型SOCKETuint64 与printf接受int矛盾
        }
        if (proxySocket == SOCKET_ERROR) {
            printf("Socket error: %d\n", WSAGetLastError());
            break;
        }
        else {
            printf("Socket seccess: %d\n", proxySocket);
        }
        //绑定
        if (bind(proxySocket, (struct sockaddr*)&proxyAddr, addrSize) == SOCKET_ERROR) {
            printf("Failed bind:%d\n", WSAGetLastError());
            break;
        }
        //阻塞
        if (listen(proxySocket, BACKLOG) == SOCKET_ERROR) {
            printf("Listen failed:%d\n", WSAGetLastError());
            break;
        }
        printf("proxy listening...\n");

        //maybe new thread
        while (1)
        {
            ////阻塞 第二次握手，通过accept来接受对方的套接字的信息
            proxyConn2Clnt = accept(proxySocket, (struct sockaddr*)&clntAddr, &addrSize);
            if (proxyConn2Clnt == SOCKET_ERROR) {
                printf("Accept failed:%d\n", WSAGetLastError());
                continue;
            }
            else {
                printf("New client %d...\n", proxyConn2Clnt);
            }

            setsockopt(proxyConn2Clnt, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));//超时返回-1

             /*基于pCtx产生一个新的ssl*/
            pSSL2Clnt = SSL_new(pCtx2Clnt);
            if (NULL == pSSL2Clnt)
            {
                printf("%s %d error=%d\n", __func__, __LINE__, errno);
                continue;
            }
            /*将连接的socket加入到ssl*/
            SSL_set_fd(pSSL2Clnt, proxyConn2Clnt);

            /*建立ssl连接（握手）*/
            if (iRet = SSL_accept(pSSL2Clnt) <= 0)
            {
                printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(SSL_get_error(pSSL2Clnt, iRet), NULL));
                continue;
            }

            //as client to server
            inet_pton(AF_INET, ipBuf, &proxyAddr2Serv.sin_addr.s_addr);
            //proxyAddr2Serv.sin_addr.S_un.S_addr = clntAddr.sin_addr.S_un.S_addr;
            proxyAddr2Serv.sin_family = AF_INET;
            proxyAddr2Serv.sin_port = htons(PORT2SERV);

            if (wsaStarted == 0) {
                proxySocket2Serv = socket(AF_INET, SOCK_STREAM, 0);//协议族，Socket类型，创建了可识别套接字
                //socke 返回类型SOCKETuint64 与printf接受int矛盾
            }
            if (proxySocket2Serv == SOCKET_ERROR) {
                printf("client socket error: %d\n", WSAGetLastError());
                closesocket(proxySocket2Serv);
                continue;
            }
            else {
                printf("client socket seccess: %d\n", proxySocket2Serv);
            }
            setsockopt(proxySocket2Serv, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));//超时返回-1
            //向服务器发出连接请求
            if (
                connect(proxySocket2Serv, (struct sockaddr*)&proxyAddr2Serv, addrSize)
                == INVALID_SOCKET
                ) {
                //printf("%d", r);
                printf("Connect failed: %d\n", WSAGetLastError());
                closesocket(proxySocket2Serv);//关闭
                closesocket(proxyConn2Clnt);
                continue;
            }
            /*基于pCtx产生一个新的ssl*/
            pSSL2Serv = SSL_new(pCtx2Serv);
            if (NULL == pSSL2Serv)
            {
                printf("%s %d error=%d\n", __func__, __LINE__, errno);
                break;
            }
            /*将连接的socket加入到ssl*/
            SSL_set_fd(pSSL2Serv, proxySocket2Serv);

            /*ssl握手*/
            iRet = SSL_connect(pSSL2Serv);
            if (iRet < 0)
            {
                printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(SSL_get_error(pSSL2Serv, iRet), NULL));
                break;
            }
#if VIRIFY_SERVER_CA		
            /*获取验证对端证书的结果*/
            if (X509_V_OK != SSL_get_verify_result(pSSL2Serv))
            {
                printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(ERR_get_error(), NULL));
                break;
            }

            /*获取对端证书*/
            pX509Cert = SSL_get_peer_certificate(pSSL2Serv);

            if (NULL == pX509Cert)
            {
                printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(ERR_get_error(), NULL));
                break;
            }

            /*获取证书使用者属性*/
            pX509Subject = X509_get_subject_name(pX509Cert);
            if (NULL == pX509Subject)
            {
                printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(SSL_get_error(pSSL2Serv, iRet), NULL));
                break;
            }
            char szBuf[256] = { 0 };
            char szSubject[1024] = { 0 };
            char szIssuer[256] = { 0 };
            X509_NAME_oneline(pX509Subject, szSubject, sizeof(szSubject) - 1);
            X509_NAME_oneline(X509_get_issuer_name(pX509Cert), szIssuer, sizeof(szIssuer) - 1);
            X509_NAME_get_text_by_NID(pX509Subject, NID_commonName, szBuf, sizeof(szBuf) - 1);
            printf("szSubject =%s \nszIssuer =%s\n  commonName =%s\n", szSubject, szIssuer, szBuf);
#endif		
            // delivering messege
            while (1) {
                int recvBytes = 0;
                int sendBytes = 0;
                char* transBuf;
                transBuf = (char*)malloc(BUFSIZE * sizeof(char));
                memset(transBuf, '\0', BUFSIZE);

                //from client 阻塞
                //recvBytes = recv(proxyConn2Clnt, transBuf, BUFSIZE, 0);
                recvBytes = SSL_read(pSSL2Clnt, transBuf, BUFSIZE);
                if (recvBytes > 0) {
                    printf("from clent: (%d)\n", recvBytes);
                    //sprintf(sendBuf, BUFSIZE, "%s", recvBuf);
                }
                else {
                    printf("connection closed\n");
                    break;
                }

#if nonBlockMode
                ioctlsocket(proxyConn2Clnt, FIONBIO, &nonBlockingMode);
#endif
                while (1) {
                    //to server
                    //sendBytes = send(proxySocket2Serv, transBuf, recvBytes, 0);
                    sendBytes=SSL_write(pSSL2Serv, transBuf, strlen(transBuf));
                    if (sendBytes == SOCKET_ERROR) {
                        printf("send to server failed\n");
                        break;
                    }
                    //Sleep(2);
                    //from client
                    //recvBytes = recv(proxyConn2Clnt, transBuf, BUFSIZE, 0);
                    recvBytes = SSL_read(pSSL2Clnt, transBuf, BUFSIZE);
                    if (recvBytes > 0) {
                        printf("from clent: (%d)\n", recvBytes);
                        //sprintf(sendBuf, BUFSIZE, "%s", recvBuf);
                    }
                    else {
                        printf("receive from clent finished\n");
                        break;
                    }
                }
#if nonBlockMode
                ioctlsocket(proxyConn2Clnt, FIONBIO, &blockingMode);
#endif
                //ioctlsocket(proxySocket2Serv, FIONBIO, &nonBlockingMode);
                while (1) {
                    //from server
                    //recvBytes = recv(proxySocket2Serv, transBuf, BUFSIZE, 0);
                    recvBytes = SSL_read(pSSL2Serv, transBuf, BUFSIZE);
                    if (recvBytes > 0) {
                        printf("from server: (%d)%s\n", recvBytes, transBuf);
                        //sprintf(sendBuf, BUFSIZE, "%s", recvBuf);
                    }
                    else {
                        printf("receive from server finished\n");
                        break;
                    }
                    //to client
                    //sendBytes = send(proxyConn2Clnt, transBuf, recvBytes, 0);
                    sendBytes = SSL_write(pSSL2Clnt, transBuf, strlen(transBuf));
                    if (sendBytes == SOCKET_ERROR) {
                        printf("send to client failed\n");
                        break;
                    }
                }

                //ioctlsocket(proxySocket2Serv, FIONBIO, &blockingMode);
                //break;
                free(transBuf);
            }
            SSL_shutdown(pSSL2Clnt);
            SSL_shutdown(pSSL2Serv);
            closesocket(proxyConn2Clnt);
            closesocket(proxySocket2Serv);//关闭
        }

    } while (0);

#if VIRIFY_SERVER_CA

    if (pX509Cert){
        X509_free(pX509Cert);
    }
#endif
    if (pSSL2Serv){
        SSL_free(pSSL2Serv);
        pSSL2Serv = NULL;
    }
    if (pSSL2Clnt){
        SSL_free(pSSL2Clnt);
        pSSL2Clnt = NULL;
    }
    if (pCtx2Serv){
        SSL_CTX_free(pCtx2Serv);
        pCtx2Serv = NULL;
    }
    if (pCtx2Clnt){
        SSL_CTX_free(pCtx2Clnt);
        pCtx2Clnt = NULL;
    }
    if (proxyConn2Clnt > 0) {
        closesocket(proxyConn2Clnt);
    }
    if (proxySocket > 0) {
        closesocket(proxySocket);
    }
    if (proxySocket2Serv > 0) {
        closesocket(proxySocket2Serv);
    }

    WSACleanup();//释放资源的操作
    //free(transBuf);
    return 0;
}
