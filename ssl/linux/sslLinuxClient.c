// ca key & crt
// һ��������ǩ��
// openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365
// ��˽Կ��֤�飨��Կ��
// or openssl genpkey -algorithm RSA -out ca.key
//   openssl req -new -key ca.key -x509 -days 365 -out ca.crt

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

#define BACKLOG (5)
#define BUFSZ (65536)
#define PORT (4324)
#define VIRIFY_SERVER_CA (1)
const char *const sIP = "127.0.0.1";
// const char* const sIP = "192.168.137.1";
const char *const pCAPath = "../ca/ca.crt";

void Keylog_cb_func(const SSL *ssl, const char *line){
    FILE  * fp;
    fp = fopen("/home/rio/Documents/huawei/code/server/proxy2-transmit/ssl/linux/openssl.log", "a");
    if (fp == NULL)
    {
        printf("Failed to create log file\n");
    }
    fprintf(fp, "%s\n", line);
    fclose(fp);
}

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


void saveSessionTicket(SSL *ssl) {
    SSL_SESSION *session = SSL_get1_session(ssl);
    if (session != NULL && SSL_SESSION_is_resumable(session)) {

        FILE *file = fopen("session_ticket.bin", "wb");
        if (file) {
            PEM_write_SSL_SESSION(file,session);
            fclose(file);
        }
    // SSL_SESSION_free(session);
    }else{
        printf("sess not resumable\n");
    }
}

// 读取Session Ticket文件并判断是否过期
SSL *useSessionTicket(SSL_CTX *ctx)
{
    FILE *file = fopen("session_ticket.bin", "rb");
    SSL *ssl = SSL_new(ctx);
    if (!file)
    {
        // 文件为空或不存在，直接进行握手
        return ssl;
    }
    // 获取文件大小
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (fileSize <= 0)
    {
        // 文件为空，直接进行握手
        fclose(file);
        return ssl;
    }

    // 将Session Ticket设置到SSL对象中
    SSL_SESSION *session = PEM_read_SSL_SESSION(file, NULL, NULL, NULL);
    fclose(file);
    if (session)
    {
        // 判断Session Ticket是否过期
        time_t now = time(NULL);
        time_t session_time = SSL_SESSION_get_time(session);
        time_t session_timeout = SSL_SESSION_get_timeout(session);
        // 将过期时间格式化为可读的字符串
        time_t expiration_time = session_time + session_timeout;
        struct tm *expiration_tm = localtime(&expiration_time);

        char timeBuff[80];
        strftime(timeBuff, sizeof(timeBuff), "%Y-%m-%d %H:%M:%S", expiration_tm);
        printf("Expiration Time: %s\n", timeBuff);
        // if (expiration_time> now)
        // {
            // Session Ticket未过期，可以使用它进行握手
            SSL_set_session(ssl, session);
            return ssl;
        // }
    }

    // Session Ticket过期，或者无法解析，直接进行握手
    printf("new sess\n");
    return ssl;
}
int main()
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *pMethod = TLS_method();
    SSL_CTX *pCtx = NULL;
    SSL *pSSL = NULL;

    int iRet = -1;
    X509 *pX509Cert = NULL;
    X509_NAME *pX509Subject = NULL;

    char szBuf[256] = {0};
    char szSubject[1024] = {0};
    char szIssuer[256] = {0};

    int clientSocket;
    struct sockaddr_in serverAddr;
    char *buffer;
    buffer = (char *)malloc(BUFSZ * sizeof(char));

    do
    {
        pCtx = SSL_CTX_new(pMethod);
        if (NULL == pCtx)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }
        // EVP_PKEY_X25519
        // SSL_CTX_set1_curves_list(pCtx, "secp256r1");
        // SSL_CTX_set1_curves_list(pCtx, "X448");
        // EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime_field);
        // SSL_CTX_set_tmp_ecdh(pCtx, ecdh);
        // EC_KEY_free(ecdh);
        
        // SSL_CTX_set_options(pCtx, SSL_OP_NO_TLSv1_3);
        // SSL_CTX_set_options(pCtx, SSL_OP_NO_EXTENDED_MASTER_SECRET);//openssl 3.0
        // SSL_CTX_set_options(pCtx, SSLOPEC);
        SSL_CTX_set_block_padding(pCtx,3);
        // SSL_CTX_set_ecdh_auto(pCtx, 1);
        SSL_CTX_set_ciphersuites(pCtx,"TLS_AES_128_GCM_SHA256");
        // SSL_CTX_set_cipher_list(pCtx, "ECDHE-RSA-AES128-GCM-SHA256");
        // SSL_CTX_set_cipher_list(pCtx, "AES128-SHA256");
        // SSL_CTX_add_client_custom_ext(pCtx, TLSEXT_TYPE_signed_certificate_timestamp, NULL, NULL, NULL, NULL, NULL);
        
        // SSL_CTX_set_keylog_callback(pCtx,Keylog_cb_func);
#if VIRIFY_SERVER_CA
        if (SSL_CTX_load_verify_locations(pCtx, pCAPath, NULL) != 1)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }
        SSL_CTX_set_verify(pCtx, SSL_VERIFY_PEER, NULL);
#endif
#if 0
        if (!SSL_CTX_set_cipher_list(pCtx, "ALL"))
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;

        }
#endif

        clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSocket == -1)
        {
            perror("Socket creation failed");
            break;
        }

        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(PORT);           
        inet_pton(AF_INET, sIP, &serverAddr.sin_addr); 
        int opt = 1;
        setsockopt(clientSocket, SOL_SOCKET,SO_REUSEADDR, 
                    (const void *)&opt, sizeof(opt) ); //bind 端口复用

        if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
        {
            perror("Connection failed");
            break;
        }
        printf("socket Connected to server\n");

        // pSSL = useSessionTicket(pCtx);
        pSSL = SSL_new(pCtx);
        if (NULL == pSSL)
        {
            printf("%s %d error=%d\n", __func__, __LINE__, errno);
            break;
        }
        SSL_set_fd(pSSL, clientSocket);

        iRet = SSL_connect(pSSL);
        if (iRet < 0)
        {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                   ERR_error_string(SSL_get_error(pSSL, iRet), NULL));
            break;
        }
#if VIRIFY_SERVER_CA
        if (X509_V_OK != SSL_get_verify_result(pSSL))
        {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                   ERR_error_string(ERR_get_error(), NULL));
            break;
        }
        pX509Cert = SSL_get1_peer_certificate(pSSL);

        if (NULL == pX509Cert)
        {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                   ERR_error_string(ERR_get_error(), NULL));
            break;
        }
        pX509Subject = X509_get_subject_name(pX509Cert);
        if (NULL == pX509Subject)
        {
            printf("%s %d iRet=%d %s\n", __func__, __LINE__, iRet,
                   ERR_error_string(SSL_get_error(pSSL, iRet), NULL));
            break;
        }

        X509_NAME_oneline(pX509Subject, szSubject, sizeof(szSubject) - 1);
        X509_NAME_oneline(X509_get_issuer_name(pX509Cert), szIssuer, sizeof(szIssuer) - 1);
        X509_NAME_get_text_by_NID(pX509Subject, NID_commonName, szBuf, sizeof(szBuf) - 1);
        printf("szSubject =%s \nszIssuer =%s\n  commonName =%s\n", szSubject, szIssuer, szBuf);
#endif

        if(SSL_session_reused(pSSL)){
            printf("sess reuse success\n");
        }
        printf("Type 'quit' to exit\n");

        while (1)
        {
            // char message[1024];
            memset(buffer, '\0', BUFSZ);
            printf("Enter a message: ");
            fgets(buffer, BUFSZ, stdin);

            // send(clientSocket, buffer, strlen(buffer), 0);
            SSL_write(pSSL, buffer, strlen(buffer));

            if (strncmp(buffer, "quit", 4) == 0)
            {
                printf("Quitting...\n");
                break;
            }
            // recv(clientSocket, buffer, BUFSZ, 0);
            SSL_read(pSSL, buffer, BUFSZ);
            printf("Server response: %s\n", buffer);
        }
        if(!SSL_session_reused(pSSL)){
            printf("saving sess ticket\n");
            saveSessionTicket(pSSL);
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
        close(clientSocket);
    }
    free(buffer);
    return 0;
}
