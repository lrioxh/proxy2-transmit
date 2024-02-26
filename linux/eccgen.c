#include <openssl/evp.h>
#include <openssl/ec.h>
#define PROXY_FREE(ptr, free_func) \
    do { \
        if ((ptr) != NULL) { \
            free_func(ptr); \
            (ptr) = NULL; \
        } \
    } while (0)
// #define PROXY_FREE(ptr)    do{if ((ptr) != NULL) {free(ptr); ptr=NULL;}} while (0)
int EC_Curve2Key(int curve_nid, uint8_t **pub_key_str,size_t *pub_key_len, uint8_t **priv_key_str,size_t *priv_key_len)
{
    EC_KEY *key = EC_KEY_new_by_curve_name_ex(NULL,NULL,curve_nid);
    if (!key) {
        return 0;
    }

    if (EC_KEY_generate_key(key) != 1) {
        EC_KEY_free(key);
        return 0;
    }
    const EC_POINT *pub_key = EC_KEY_get0_public_key(key);
    const BIGNUM *priv_key = EC_KEY_get0_private_key(key);
    // 获取公钥和私钥的长度
    *pub_key_len = EC_POINT_point2oct(
        EC_KEY_get0_group(key), pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL
    );
    *priv_key_len = BN_num_bytes(priv_key);
    *pub_key_str=OPENSSL_malloc(*pub_key_len);
    *priv_key_str=OPENSSL_malloc(*priv_key_len);

    if(!EC_POINT_point2oct(EC_KEY_get0_group(key), pub_key, POINT_CONVERSION_UNCOMPRESSED,*pub_key_str,pub_key_len, NULL)||
       !BN_bn2bin(priv_key,priv_key_str)){
            EC_KEY_free(key);
            return 0;
        }
    EC_KEY_free(key);
    return 1;
}

// EVP_PKEY_get1_EC_KEY();
int Curve2Key(int type, int curve_nid, uint8_t **pub_key_buf,size_t *pub_key_len, EVP_PKEY **privkey){
    // EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(type, NULL);
    if (
        EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve_nid) <= 0 ||
        EVP_PKEY_keygen(pctx, privkey) <= 0 || *privkey == NULL)
    {
        EVP_PKEY_CTX_free(pctx);
        // handle_error("EVP_PKEY_CTX generate error");
        return 0;
    }
    int ret=1;

        // EVP_PKEY_get_octet_string_param(*privkey,
        //                                 OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
        //                                 NULL, 0, pub_key_len);

        *pub_key_len=EVP_PKEY_get1_encoded_public_key(*privkey,pub_key_buf);
        if(!*pub_key_len
        // ||!EVP_PKEY_get_raw_private_key(key, *priv_key_buf, priv_key_len)
        ){
                ret = 0;
        }
    // }
    EVP_PKEY_CTX_free(pctx);
    // EVP_PKEY_free(key);
    return ret;
}
// int EcKeyGen(int type,int nid,uint8_t **pubKey,size_t *publen,uint8_t **privKey,size_t *privlen)
// {
//     int ret;
//     if (type == EVP_PKEY_EC)
//     {
//         ret = EC_Curve2Key(nid,pubKey,publen,privKey,privlen);
//     }
//     else
//     {
//         ret = X_Curve2Key(type,nid,pubKey,publen,privKey,privlen);
//     }
//     if (!ret){
//         return 0;
//     }
//     EVP_PKEY *outp = EVP_PKEY_new_raw_private_key(type, NULL, privKey, privlen);
//     if(outp == NULL)
//     {
//         // EVP_PKEY_free(key);
//         // handle_error("curve key Extraction failed");
//         return 0;
//     }
//     EVP_PKEY_free(outp);
//     return ret;

// }
int main()
{
    uint8_t *pubKey;
    EVP_PKEY *privkey=NULL;
    size_t publen;
    size_t privlen;
    // Curve2Key(NID_X448,NID_X448,&pubKey,&publen,&privkey);
    // printf("X448 Public Key: %s\n", pubKey);
    // printf("X448 Private Key: %s\n", privKey);

    // memset(pubKey,0,100);
    // memset(privKey,0,100);
    Curve2Key(EVP_PKEY_EC,NID_secp384r1,&pubKey,&publen,&privkey);
    // printf("secp384r1 Public Key: %s\n", pubKey);
    // printf("secp384r1 Private Key: %s\n", privKey);

    unsigned char *pms = NULL;
    size_t pmslen = 0;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(NULL, privkey, NULL);

    // EVP_PKEY_CTX_new_id;//type
    // EVP_PKEY_CTX_set_ec_paramgen_curve_nid;
    // EVP_PKEY_paramgen_init;
    // EVP_PKEY_set1_tls_encoded_point;
    EVP_PKEY *pubkey = EVP_PKEY_new();
    EVP_PKEY_copy_parameters(pubkey, privkey);
    EVP_PKEY_set1_encoded_public_key(pubkey, pubKey, publen);

    // EVP_PKEY *pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_EC, NULL, pubKey, publen);

    if (EVP_PKEY_derive_init(pctx) <= 0
        || EVP_PKEY_derive_set_peer(pctx, pubkey) <= 0
        || EVP_PKEY_derive(pctx, NULL, &pmslen) <= 0) {
        // SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        // goto err;
        printf("e1");
    }

    // if (SSL_IS_TLS13(s) &&  EVP_PKEY_is_a(privkey, "DH"))
    //     EVP_PKEY_CTX_set_dh_pad(pctx, 1);

    pms = OPENSSL_malloc(pmslen);
    // if (pms == NULL) {
        // SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        // goto err;
    // }

    if (EVP_PKEY_derive(pctx, pms, &pmslen) <= 0) {
        // SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        // goto err;
        printf("e2");
    }
    OPENSSL_free(pms);
    PROXY_FREE(pubkey,EVP_PKEY_free);
    if(pms==NULL){

        printf("e2");
    }
    if(pms){
        printf("e2");

    }
    return 0;
}
