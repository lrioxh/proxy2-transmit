//ca key & crt
// 一步生成自签名
//openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365
// 先私钥后证书（公钥）
//or openssl genpkey -algorithm RSA -out ca.key
//   openssl req -new -key ca.key -x509 -days 365 -out ca.crt


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

#define BACKLOG                 (5)	//最大监听数
#define BUFSZ                   (10240)
#define PORT                    (4322)
#define VIRIFY_SERVER_CA        (1)
const char* const sIP = "127.0.0.1";
const char* const pCAPath = "../ca/ca.crt";

int main() {

    /*SSL库初始化（一个进程只初始化一次）*/
    SSL_library_init();
    /*载入所有ssl错误消息*/
    SSL_load_error_strings();
    /*载入所有ssl算法*/
    OpenSSL_add_all_algorithms();

    const SSL_METHOD* pMethod = TLSv1_2_method();
    SSL_CTX* pCtx = NULL;
    SSL* pSSL = NULL;

    int iRet = -1;
    X509* pX509Cert = NULL;
    X509_NAME* pX509Subject = NULL;

    char szBuf[256] = { 0 };
    char szSubject[1024] = { 0 };
    char szIssuer[256] = { 0 };

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    int clientSocket;
    struct sockaddr_in serverAddr;
    char* buffer;
    buffer = (char*)malloc(BUFSZ * sizeof(char));

    do {

        /*初始化SSL上下文环境变量函数*/
        pCtx = SSL_CTX_new(pMethod);
        if (NULL == pCtx)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;

        }
#if VIRIFY_SERVER_CA
        /*加载CA证书（对端证书需要用CA证书来验证）*/
        if (SSL_CTX_load_verify_locations(pCtx, pCAPath, NULL) != 1)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }
     
        /*设置对端证书验证*/
        SSL_CTX_set_verify(pCtx, SSL_VERIFY_PEER, NULL);
#endif
#if 0
        if (!SSL_CTX_set_cipher_list(pCtx, "ALL"))
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;

        }
#endif

        // 创建客户端socket
        clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSocket == -1) {
            perror("Socket creation failed");
            break;
            //exit(EXIT_FAILURE);
        }

        // 设置服务器地址结构
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(PORT);  // 与服务器相同的端口
        inet_pton(AF_INET, sIP, &serverAddr.sin_addr);  // 服务器的IP地址

        // 连接到服务器
        if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
            perror("Connection failed");
            //closesocket(clientSocket);
            break;
            //exit(EXIT_FAILURE);
        }
        printf("Connected to server\n");

        /*基于pCtx产生一个新的ssl*/
        pSSL = SSL_new(pCtx);
        if (NULL == pSSL)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }
        /*将连接的socket加入到ssl*/
        SSL_set_fd(pSSL, clientSocket);

        /*ssl握手*/
        iRet = SSL_connect(pSSL);
        if (iRet < 0)
        {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(SSL_get_error(pSSL, iRet), NULL));
            break;
        }
#if VIRIFY_SERVER_CA		
        /*获取验证对端证书的结果*/
        if (X509_V_OK != SSL_get_verify_result(pSSL))
        {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(ERR_get_error(), NULL));
            break;
        }

        /*获取对端证书*/
        pX509Cert = SSL_get_peer_certificate(pSSL);

        if (NULL == pX509Cert)
        {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(ERR_get_error(), NULL));
            break;
        }

        /*获取证书使用者属性*/
        pX509Subject = X509_get_subject_name(pX509Cert);
        if (NULL == pX509Subject)
        {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(SSL_get_error(pSSL, iRet), NULL));
            break;
        }

        X509_NAME_oneline(pX509Subject, szSubject, sizeof(szSubject) - 1);
        X509_NAME_oneline(X509_get_issuer_name(pX509Cert), szIssuer, sizeof(szIssuer) - 1);
        X509_NAME_get_text_by_NID(pX509Subject, NID_commonName, szBuf, sizeof(szBuf) - 1);
        printf("szSubject =%s \nszIssuer =%s\n  commonName =%s\n", szSubject, szIssuer, szBuf);
#endif		

        printf("Type 'quit' to exit\n");

        while (1) {
            //char message[1024];            
            memset(buffer, '\0', BUFSZ);
            printf("Enter a message: ");
            fgets(buffer, BUFSZ, stdin);

            // 发送消息给服务器
            //send(clientSocket, buffer, strlen(buffer), 0);
            SSL_write(pSSL, buffer, strlen(buffer));

            // 退出条件
            if (strncmp(buffer, "quit", 4) == 0) {
                printf("Quitting...\n");
                break;
            }

            // 接收服务器的响应
            //char response[1024];
            //recv(clientSocket, buffer, BUFSZ, 0);
            SSL_read(pSSL, buffer, BUFSZ);
            printf("Server response: %s\n", buffer);
        }
        SSL_shutdown(pSSL);

    } while (0);


#if VIRIFY_SERVER_CA

    if (pX509Cert)
    {
        X509_free(pX509Cert);
    }
#endif
    if (pSSL)
    {
        SSL_free(pSSL);
        pSSL = NULL;
    }
    if (pCtx)
    {
        SSL_CTX_free(pCtx);
        pCtx = NULL;
    }

    if (clientSocket > 0)
    {
        closesocket(clientSocket);
    }
    WSACleanup();//释放资源的操作
    //closesocket(clientSocket);
    free(buffer);
    return 0;
}

