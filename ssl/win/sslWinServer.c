//server key & crt
// 私钥
//openssl genpkey -algorithm RSA -out server.key
// 签名请求
//openssl req -new -key server.key -out server.csr
// ca签名
//openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365
// 自签名
//openssl x509 -req -days 365 -in server.csr -signkey ca.key -out server.crt

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
#define PORT                    (4321)

const char* const certificate_path = "../ca/server.crt";
const char* const private_key_path = "../ca/server.key";
const char* const password = "123456";

int main() {


    /*SSL库初始化（一个进程只初始化一次）*/
    SSL_library_init();
    /*载入所有ssl错误消息*/
    SSL_load_error_strings();
    /*载入所有ssl算法*/
    OpenSSL_add_all_algorithms();

    const SSL_METHOD* pMethod = TLSv1_2_server_method();
    SSL_CTX* pCtx = NULL;
    SSL* pSSL = NULL;
    int iRet = 0;

    //socket
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    int serverSocket, clientSocket;
    int bytesRead = 0;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
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

        /* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
        if (SSL_CTX_use_certificate_file(pCtx, certificate_path, SSL_FILETYPE_PEM) <= 0)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }
#if 1		
        /*设置私钥的解锁密码*/
        SSL_CTX_set_default_passwd_cb_userdata(pCtx, password);
#endif
        /* 载入用户私钥 */
        if (SSL_CTX_use_PrivateKey_file(pCtx, private_key_path, SSL_FILETYPE_PEM) <= 0)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }

        /* 检查用户私钥是否正确 */
        if (SSL_CTX_check_private_key(pCtx) <= 0)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }

        /*证书验证*/
        SSL_CTX_set_verify(pCtx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_options(pCtx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        SSL_CTX_set_mode(pCtx, SSL_MODE_AUTO_RETRY);


        // 创建服务器socket
        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket == -1) {
            printf("%s %d Socket creation error=%d\n", __func__, __LINE__, errno);
            break;
        }

        // 设置服务器地址结构
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(PORT);  // 选择一个合适的端口

        // 绑定socket到服务器地址
        if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
            printf("%s %d Binding error=%d\n", __func__, __LINE__, errno);
            break;
            //perror("Binding failed");
            //closesocket(serverSocket);
            //exit(EXIT_FAILURE);
        }

        // 监听连接请求
        if (listen(serverSocket, BACKLOG) == -1) {
            printf("%s %d Listening error=%d\n", __func__, __LINE__, errno);
            break;
            //perror("Listening failed");
            //closesocket(serverSocket);
            //exit(EXIT_FAILURE);
        }

        

        while (1) {
            // 接受客户端连接
            printf("Server listening...\n");
            clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &addrLen);
            if (clientSocket == -1) {
                perror("Accepting connection failed");
                continue;
            }

            printf("Client connected\n");

            /*基于pCtx产生一个新的ssl*/
            pSSL = SSL_new(pCtx);
            if (NULL == pSSL)
            {
                printf("%s %d error=%d\n", __func__, __LINE__, errno);
                continue;
            }
            /*将连接的socket加入到ssl*/
            SSL_set_fd(pSSL, clientSocket);
            
            /*建立ssl连接（握手）*/
            if (iRet=SSL_accept(pSSL) <= 0)
            {
                printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet, ERR_error_string(SSL_get_error(pSSL, iRet), NULL));
                continue;
            }

            // 处理通信
            while (1) {

                memset(buffer, '\0', BUFSZ);

                //bytesRead = recv(clientSocket, buffer, BUFSZ, 0);
                bytesRead = SSL_read(pSSL, buffer, BUFSZ);
                if (bytesRead <= 0) {
                    printf("Client disconnected\n");
                //    closesocket(clientSocket);
                    break;
                }
                printf("server recv text :%s \n", buffer);
                // 检查是否为关闭消息
                if (strncmp(buffer, "quit", 4) == 0) {
                    printf("Client sent quit message\n");
                    // 这里可以进行一些清理工作，然后关闭连接
                //    closesocket(clientSocket);
                    break;
                }
                // 在这里处理接收到的数据，然后构造要发送回客户端的响应
                //sprintf(buffer, "%s-server", buffer);
                sprintf(buffer + strlen(buffer) - 1, "-server");
                //send(clientSocket, buffer, bytesRead + strlen("-server"), 0);
                SSL_write(pSSL, buffer, strlen(buffer));

            }
            /*关闭ssl连接*/
            SSL_shutdown(pSSL);
            closesocket(clientSocket);
        }

    } while (0);

    
    closesocket(serverSocket);
    WSACleanup();//释放资源的操作
    free(buffer);
    return 0;
}