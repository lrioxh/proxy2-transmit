// server key & crt
//  ˽Կ
// openssl genpkey -algorithm RSA -out server.key
//  ǩ������
// openssl req -new -key server.key -out server.csr
//  caǩ��
// openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days
// 365
//  ��ǩ��
// openssl x509 -req -days 365 -in server.csr -signkey ca.key -out server.crt
// https://learn.microsoft.com/zh-cn/azure/application-gateway/self-signed-certificates

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

#define BACKLOG (5) // ��������
#define BUFSZ (65536)
#define PORT (4321)
#define USE_EARLY_DATA (1)

const char* const certificate_path = "../ca/server.crt";
const char* const private_key_path = "../ca/server.key";

void Keylog_cb_func(const SSL* ssl, const char* line)
{
    FILE* fp;
    fp = fopen("/home/rio/Documents/huawei/code/server/proxy2-transmit/ssl/linux/openssl.log", "a");
    if (fp == NULL)
    {
        printf("Failed to create log file\n");
    }
    fprintf(fp, "%s\n", line);
    fclose(fp);
}
int main()
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD* pMethod = TLS_server_method();
    SSL_CTX* pCtx = NULL;
    SSL* pSSL = NULL;
    int iRet = 0;
    // socket
    int serverSocket, clientSocket;
    int bytesRead = 0;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    char* buffer;
    buffer = (char*)malloc(BUFSZ * sizeof(char));

    do
    {
        pCtx = SSL_CTX_new(pMethod);

        if (NULL == pCtx)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }

        if (SSL_CTX_use_certificate_file(pCtx, certificate_path, SSL_FILETYPE_PEM) <= 0)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }

        if (SSL_CTX_use_PrivateKey_file(pCtx, private_key_path, SSL_FILETYPE_PEM) <= 0)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }

        if (SSL_CTX_check_private_key(pCtx) <= 0)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }
        SSL_CTX_set_timeout(pCtx, 600);
        // SSL_CTX_set_max_proto_version(pCtx,TLS1_2_VERSION);
        // SSL_CTX_set_min_proto_version(pCtx,TLS1_2_VERSION);
        // SSL_CTX_set_options(pCtx, SSL_OP_NO_TLSv1_3);
        SSL_CTX_set1_curves_list(pCtx, "secp384r1:X448");
        // SSL_CTX_set_block_padding(pCtx,5);
        // SSL_CTX_set_verify(pCtx, SSL_VERIFY_NONE, NULL);
        // SSL_CTX_set_session_cache_mode(pCtx, SSL_SESS_CACHE_OFF);
        // SSL_CTX_set_cipher_list(pCtx, "ECDHE-RSA-AES128-GCM-SHA256");
        // SSL_CTX_set_ciphersuites(pCtx,"TLS_AES_128_GCM_SHA256");
        // SSL_CTX_set_cipher_list(pCtx, "AES128-SHA256");
        // SSL_CTX_add_server_custom_ext(pCtx, TLSEXT_TYPE_signed_certificate_timestamp, NULL, NULL,
        // NULL, NULL, NULL);
        SSL_CTX_set_mode(pCtx, SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_keylog_callback(pCtx, Keylog_cb_func);
#if USE_EARLY_DATA
        SSL_CTX_set_max_early_data(pCtx, 64);
        SSL_CTX_sess_set_cache_size(pCtx, 64);
#endif

        // socket
        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket == -1)
        {
            printf("%s %d Socket creation error=%d\n", __func__, __LINE__, errno);
            break;
        }
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(PORT);
        int opt = 1;
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const void*)&opt,
                   sizeof(opt)); // bind 端口复用

        if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1)
        {
            printf("%s %d Binding error=%d\n", __func__, __LINE__, errno);
            break;
        }
        if (listen(serverSocket, BACKLOG) == -1)
        {
            printf("%s %d Listening error=%d\n", __func__, __LINE__, errno);
            break;
        }
        while (1)
        {
            printf("Server listening...\n");
            clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &addrLen);
            if (clientSocket == -1)
            {
                perror("Accepting connection failed");
                continue;
            }
            printf("Client connected\n");

            pSSL = SSL_new(pCtx);
            if (NULL == pSSL)
            {
                printf("%s %d error=%d\n", __func__, __LINE__, errno);
                continue;
            }
            SSL_set_fd(pSSL, clientSocket);

#if USE_EARLY_DATA
            int write_header = 1, edret = SSL_READ_EARLY_DATA_ERROR;
            size_t readbytes = 0;
            while (edret != SSL_READ_EARLY_DATA_FINISH)
            {
                memset(buffer, '\0', BUFSZ);
                for (;;)
                {
                    edret = SSL_read_early_data(pSSL, buffer, BUFSZ, &readbytes);
                    if (edret != SSL_READ_EARLY_DATA_ERROR) break;

                    switch (SSL_get_error(pSSL, 0))
                    {
                        case SSL_ERROR_WANT_WRITE:
                        case SSL_ERROR_WANT_ASYNC:
                        case SSL_ERROR_WANT_READ:
                            /* Just keep trying - busy waiting */
                            continue;
                        default: printf("Error reading early data\n"); goto earlyDone;
                    }
                }
                if (readbytes > 0)
                {
                    if (write_header)
                    {
                        printf("Early data received:\n");
                        write_header = 0;
                    }
                    printf(" %s ", buffer);
                    sprintf(buffer + strlen(buffer), "-server");
                    // SSL_write_early_data(pSSL, buffer, strlen(buffer), &readbytes);
                }
            }
            if (write_header)
            {
                if (SSL_get_early_data_status(pSSL) == SSL_EARLY_DATA_NOT_SENT){
                    printf("No early data received\n");
                }else{
                    printf("Early data was rejected\n");
                    // SSL_write(pSSL,"early data rejected", 19);
                }
            }
            else
            {
                printf("\nEnd of early data\n");
            }
        earlyDone:
#endif
            if (iRet = SSL_accept(pSSL) <= 0)
            {
                printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                       ERR_error_string(SSL_get_error(pSSL, iRet), NULL));
                continue;
            }
            while (1)
            {
                memset(buffer, '\0', BUFSZ);
                // bytesRead = recv(clientSocket, buffer, BUFSZ, 0);
                bytesRead = SSL_read(pSSL, buffer, BUFSZ);
                if (bytesRead <= 0)
                {
                    printf("Client disconnected\n");
                    //    closesocket(clientSocket);
                    break;
                }
                printf("server recv text :%s \n", buffer);
                if (strncmp(buffer, "quit", 4) == 0)
                {
                    printf("Client sent quit message\n");
                    //    closesocket(clientSocket);
                    break;
                }
                sprintf(buffer + strlen(buffer), "-server");
                // send(clientSocket, buffer, bytesRead + strlen("-server"), 0);
                SSL_write(pSSL, buffer, strlen(buffer));
            }
            SSL_shutdown(pSSL);
            close(clientSocket);
        }
    } while (0);

    close(serverSocket);
    free(buffer);
    return 0;
}