#include <stdio.h>
#include <openssl/pem.h>
// #include <openssl/x509.h>
const char *const certificate_path = "../ssl/ca/proxy.crt";

void print_public_key(X509 *cert)
{
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    if (pubkey)
    {
        switch (EVP_PKEY_id(pubkey))
        {
        case EVP_PKEY_RSA:
        {
            RSA *rsa = EVP_PKEY_get1_RSA(pubkey);
            if (rsa)
            {
                printf("公钥:\n");
                RSA_print_fp(stdout, rsa, 0);
            }
            RSA_free(rsa);
            break;
        }
        default:
            printf("未知的公钥类型\n");
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

void print_hex(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02X", buf[i]);
    }
}

int main()
{
    FILE *cert_file;
    X509 *cert;

    // 打开证书文件
    cert_file = fopen(certificate_path, "rb");
    if (!cert_file)
    {
        fprintf(stderr, "无法打开证书文件\n");
        return 1;
    }

    // 读取证书
    cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if (!cert)
    {
        fprintf(stderr, "无法解析证书\n");
        fclose(cert_file);
        return 1;
    }

    // 获取证书的二进制比特流
    // BIO *bio = BIO_new(BIO_s_mem());
    // i2d_X509_bio(bio, cert);
    // unsigned char bytes[10240]={'\0'};
    unsigned char *bytes=NULL;
    // bytes = OPENSSL_malloc(10240);
    // unsigned char *bytes = malloc(10240);
    // memset(bytes,'\0',102410);
    // if (bytes != NULL)
    {
        int length = i2d_X509(cert, &bytes);
        if (length > 0)
        {
            // 处理成功的情况
            print_hex(bytes, length);
            OPENSSL_free(bytes);
        }
        else
        {
            fprintf(stderr, "i2d_X509 调用失败\n");
            // i2d_X509 调用失败，需要处理错误
        }
        // OPENSSL_free(bytes);
        // bytes = NULL;
    }
    // else
    // {
    //     // 内存分配失败，需要处理错误
    //     fprintf(stderr, "内存分配失败\n");
    //     // bytes = NULL;
    // }
    // bytes=OPENSSL_malloc(2048);
    // int length;
    // length = i2d_X509(cert, &bytes);
    

    // BUF_MEM *bptr;
    // BIO_get_mem_ptr(bio, &bptr);
    // printf();

    // 打印公钥和通用名
    // print_public_key(cert);
    // print_subject_info(cert);

    // 关闭资源
    // BIO_free(bio);
    // OPENSSL_free(bytes);
    X509_free(cert);
    fclose(cert_file);

    return 0;
}
