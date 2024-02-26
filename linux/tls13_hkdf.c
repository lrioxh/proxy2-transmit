

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: \n", label);
    for (size_t i = 0; i < len; i++)
    {
        if (i % 16 == 0)
        {
            printf(" ");
        }
        printf("%02X", data[i]);
    }
    printf("\n");
}

# define EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND  0
# define EVP_KDF_HKDF_MODE_EXTRACT_ONLY        1
# define EVP_KDF_HKDF_MODE_EXPAND_ONLY         2
static const unsigned char default_zeros[EVP_MAX_MD_SIZE];
static const uint8_t label_prefix[] = "tls13 ";
typedef struct {
    void *provctx;//??
    int mode;
    // PROV_DIGEST digest;//md
    unsigned char *salt;
    size_t salt_len;
    unsigned char *key;
    size_t key_len;
    unsigned char info[1024];
    size_t info_len;
} KDF_HKDF;

unsigned char hex_char_to_byte(char hex)
{
    if (hex >= '0' && hex <= '9')
    {
        return hex - '0';
    }
    else if (hex >= 'a' && hex <= 'f')
    {
        return hex - 'a' + 10;
    }
    else if (hex >= 'A' && hex <= 'F')
    {
        return hex - 'A' + 10;
    }
    // Handle invalid characters here, e.g., return 0 or throw an error
    return 0;
}

void hex_string_to_bytes(const char *hex_string, unsigned char *byte_array)
{
    size_t len = strlen(hex_string);
    if (len % 2 != 0)
    {
        // Handle odd-length hex strings
        // You can choose to return an error or pad with a leading 0
        // In this example, we'll return an error
        printf("Invalid hex string length\n");
        return;
    }

    for (size_t i = 0; i < len / 2; i++)
    {
        byte_array[i] =
            (hex_char_to_byte(hex_string[i * 2]) << 4) | hex_char_to_byte(hex_string[i * 2 + 1]);
    }
}
uint8_t *NumToByte(size_t num, uint8_t *out, size_t outLen)
{
    for (int i = outLen - 1; i >= 0; i--)
    {
        out[i] = num & 0xFF; // 取最低8位
        num >>= 8;           // 向右移动8位
    }
    return out;
}

int tls13_HKDF_expand(const EVP_MD *md, uint8_t *secret,
                             uint8_t *label, size_t labellen,
                             uint8_t *data, size_t datalen,
                             uint8_t *out, size_t outlen)
{
    int ret;
    size_t secretlen;
    if ((ret = EVP_MD_get_size(md)) <= 0) {
        // handle_error("");
        return 0;
    }
    secretlen = (size_t)ret;
    ret = prov_tls13_HKDF_expand(md,secret,secretlen,
                                label_prefix,sizeof(label_prefix) - 1,
                                label,labellen, data,datalen,
                                out,outlen) <= 0;
    if (ret != 0) {
        // handle_error("HKDF_expand error");
    }
    return ret == 0;
}

/*
 * Given the previous secret |prevsecret| and a new input secret |insecret| of
 * length |insecretlen|, generate a new secret and store it in the location
 * pointed to by |outsecret|. Returns 1 on success  0 on failure.
 */
int tls13_SecGen(const EVP_MD *md,
                          uint8_t *prevsecret,
                          uint8_t *insecret,
                          size_t insecretlen,
                          uint8_t *outsecret)
{
    size_t mdlen, prevsecretlen;
    int mdleni;
    int ret;
    static const char derived_secret_label[] = "derived";
    uint8_t preextractsec[EVP_MAX_MD_SIZE];

    mdleni = EVP_MD_get_size(md);
    /* Ensure cast to size_t is safe */
    if (mdleni < 0) {
        return 0;
    }
    mdlen = (size_t)mdleni;

    ret = prov_tls13_HKDF_generate_secret(md,prevsecret,mdlen,insecret,insecretlen,
                                        label_prefix,sizeof(label_prefix) - 1,
                                        derived_secret_label,sizeof(derived_secret_label) - 1,
                                        outsecret,mdlen) <= 0;
    if (ret != 0) {
        // handle_error("hkdf_generate_secret error");
    }
    return ret == 0;
}
/*
 * Refer to "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)"
 * Section 2.2 (https://tools.ietf.org/html/rfc5869#section-2.2).
 *
 * 2.2.  Step 1: Extract
 *
 *   HKDF-Extract(salt, IKM) -> PRK
 *
 *   Options:
 *      Hash     a hash function; HashLen denotes the length of the
 *               hash function output in octets
 *
 *   Inputs:
 *      salt     optional salt value (a non-secret random value);
 *               if not provided, it is set to a string of HashLen zeros.
 *      IKM      input keying material
 *
 *   Output:
 *      PRK      a pseudorandom key (of HashLen octets)
 *
 *   The output PRK is calculated as follows:
 *
 *   PRK = HMAC-Hash(salt, IKM)
 */
static int HKDF_Extract(const EVP_MD *evp_md,
                        uint8_t *salt, size_t salt_len,
                        uint8_t *ikm, size_t ikm_len,
                        uint8_t *prk, size_t prk_len)
{
    int sz = EVP_MD_size(evp_md);

    if (sz < 0)
        return 0;
    if (prk_len != (size_t)sz) {
        // ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_OUTPUT_BUFFER_SIZE);
        return 0;
    }
    /* calc: PRK = HMAC-Hash(salt, IKM) */
    return HMAC(evp_md, salt, salt_len, ikm, ikm_len, prk, NULL) != NULL;
}

/*
 * Refer to "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)"
 * Section 2.3 (https://tools.ietf.org/html/rfc5869#section-2.3).
 *
 * 2.3.  Step 2: Expand
 *
 *   HKDF-Expand(PRK, info, L) -> OKM
 *
 *   Options:
 *      Hash     a hash function; HashLen denotes the length of the
 *               hash function output in octets
 *
 *   Inputs:
 *      PRK      a pseudorandom key of at least HashLen octets
 *               (usually, the output from the extract step)
 *      info     optional context and application specific information
 *               (can be a zero-length string)
 *      L        length of output keying material in octets
 *               (<= 255*HashLen)
 *
 *   Output:
 *      OKM      output keying material (of L octets)
 *
 *   The output OKM is calculated as follows:
 *
 *   N = ceil(L/HashLen)
 *   T = T(1) | T(2) | T(3) | ... | T(N)
 *   OKM = first L octets of T
 *
 *   where:
 *   T(0) = empty string (zero length)
 *   T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
 *   T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
 *   T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
 *   ...
 *
 *   (where the constant concatenated to the end of each T(n) is a
 *   single octet.)
 */
static int HKDF_Expand(const EVP_MD *evp_md,
                       uint8_t *prk, size_t prk_len,
                       uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len)
{
    HMAC_CTX *hmac={0};
    int ret = 0, sz;
    unsigned int i;
    uint8_t prev[EVP_MAX_MD_SIZE];
    size_t done_len = 0, dig_len, n;

    sz = EVP_MD_size(evp_md);
    if (sz <= 0)
        return 0;
    dig_len = (size_t)sz;

    /* calc: N = ceil(L/HashLen) */
    n = okm_len / dig_len;
    if (okm_len % dig_len)
        n++;

    if (n > 255 || okm == NULL)
        return 0;

    if ((hmac = HMAC_CTX_new()) == NULL)
        return 0;
    
    // hmac->md=NULL;
    if (!HMAC_Init_ex(hmac, prk, prk_len, evp_md, NULL))
        goto err;
    for (i = 1; i <= n; i++) {
        size_t copy_len;
        const uint8_t ctr = i;

        /* calc: T(i) = HMAC-Hash(PRK, T(i - 1) | info | i) */
        if (i > 1) {
            if (!HMAC_Init_ex(hmac, NULL, 0, NULL, NULL))
                goto err;

            if (!HMAC_Update(hmac, prev, dig_len))
                goto err;
        }

        if (!HMAC_Update(hmac, info, info_len))
            goto err;

        if (!HMAC_Update(hmac, &ctr, 1))
            goto err;

        if (!HMAC_Final(hmac, prev, NULL))
            goto err;

        copy_len = (done_len + dig_len > okm_len) ?
                       okm_len - done_len :
                       dig_len;

        memcpy(okm + done_len, prev, copy_len);

        done_len += copy_len;
    }
    ret = 1;

 err:
    OPENSSL_cleanse(prev, sizeof(prev));
    HMAC_CTX_free(hmac);
    return ret;
}


int prov_tls13_HKDF_generate_secret(const EVP_MD *md,
                                           const uint8_t *prevsecret,
                                           size_t prevsecretlen,
                                           const uint8_t *insecret,
                                           size_t insecretlen,
                                           const uint8_t *prefix,
                                           size_t prefixlen,
                                           const uint8_t *label,
                                           size_t labellen,
                                           uint8_t *out, size_t outlen)
{
    size_t mdlen;
    int ret;
    uint8_t preextractsec[EVP_MAX_MD_SIZE];
    /* Always filled with zeros */
    static const uint8_t default_zeros[EVP_MAX_MD_SIZE];

    ret = EVP_MD_get_size(md);
    /* Ensure cast to size_t is safe */
    if (ret <= 0)
        return 0;
    mdlen = (size_t)ret;

    if (insecret == NULL) {
        insecret = default_zeros;
        insecretlen = mdlen;
    }
    if (prevsecret == NULL) {
        prevsecret = default_zeros;
        prevsecretlen = 0;
    } else {
        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        uint8_t hash[EVP_MAX_MD_SIZE];

        /* The pre-extract derive step uses a hash of no messages */
        if (mctx == NULL
                || EVP_DigestInit_ex(mctx, md, NULL) <= 0
                || EVP_DigestFinal_ex(mctx, hash, NULL) <= 0) {
            EVP_MD_CTX_free(mctx);
            return 0;
        }
        EVP_MD_CTX_free(mctx);

        /* Generate the pre-extract secret */
        if (!prov_tls13_HKDF_expand(md, prevsecret, mdlen,
                                    prefix, prefixlen, label, labellen,
                                    hash, mdlen, preextractsec, mdlen))
            return 0;
        prevsecret = preextractsec;
        prevsecretlen = mdlen;
    }

    ret = HKDF_Extract(md, prevsecret, prevsecretlen,
                       insecret, insecretlen, out, outlen);

    if (prevsecret == preextractsec)
        OPENSSL_cleanse(preextractsec, mdlen);
    return ret;
}


int prov_tls13_HKDF_expand(const EVP_MD *md,
                           const uint8_t *key, size_t keylen,
                           const uint8_t *prefix, size_t prefixlen,
                           const uint8_t *label, size_t labellen,
                           const uint8_t *hash, size_t hashlen,
                           uint8_t *out, size_t outlen)
{
    /*
     * 2 bytes for length of derived secret + 1 byte for length of combined
     * prefix and label + bytes for the label itself + 1 byte length of hash
     * + bytes for the hash itself
     */
    size_t hkdflabellen=0;
    uint8_t hkdflabel[128],*p = hkdflabel;
    p = NumToByte(outlen,p,2) + 2;
    p = NumToByte(prefixlen+labellen,p,1) + 1;
    p = memmove(p,prefix,prefixlen) + prefixlen;
    p = memmove(p,label,labellen) + labellen;
    p = NumToByte(hashlen,p,1) + 1;
    memmove(p,hash,hashlen);
    hkdflabellen=4+prefixlen+labellen+hashlen;
    
    return HKDF_Expand(md, key, keylen, hkdflabel, hkdflabellen,
                       out, outlen);
}
int main(){
    uint8_t secret[64]={0};
    uint8_t hash[64]={0};
    // uint8_t label[]="derived";
    uint8_t pms[64]={0};
    uint8_t out[64]={0};
    hex_string_to_bytes("4EA905C2A0482EB27C4F704ADBA1D97AE62D9A7360BEAC92F4A4A8DA2E725757",secret);//early
    hex_string_to_bytes("5101A9A65A1B38B3F52B0E2C74D3F69289221A683E1E7261215DF6680AF282CE",hash);
    hex_string_to_bytes("3D8C9475CA5BD9D4A81DB433C7A70521029192DE54AA1C9657BCEFD31B696865",pms);
    const EVP_MD *md=EVP_sha256();
    tls13_HKDF_expand(md,secret,"s hs traffic",12,hash,32,out,32);
    tls13_HKDF_expand(md,out,"key",3,NULL,0,out+32,16);
    print_hex("",out,64);
    // tls13_SecGen(md,secret,pms,32,out+32);
    //235 195...160 79
}