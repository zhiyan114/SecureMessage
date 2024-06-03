#include "EncryptionHandler.h"
#include<QDebug>
#include <stdio.h>
#ifdef _WIN64
// x64 bit Windows library
#include <process.h>
#include <windows.h>
#include <bcrypt.h>
#elif __linux__ || __unix__
// x64 bit Linux library
#include <unistd.h>
#include <fstream>
#endif
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/sha.h>

void RandByte(unsigned char* byteArr,int size) {

#ifdef _WIN64
    BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, byteArr, size, 0);
#elif __linux || __unix__
    // /dev/urandom grabber lol
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    urandom.read((char*)byteArr, size);
#else
    #error Unsupported Target OS (RandByte Method)
#endif
}
/*
 * Return Values:
 * 1 - Successful
 * 0 - Invalid AES Key size
*/
int Encryption::IAES::Encrypt(QByteArray Key, QByteArray Data, QByteArray * Result) {
    unsigned char IV[12];
    RandByte(IV,12);
    const EVP_CIPHER * CipherMode;
    switch(Key.size()) {
        case 16:
            CipherMode = EVP_aes_128_gcm();
            break;
        case 24:
            CipherMode = EVP_aes_192_gcm();
            break;
        case 32:
            CipherMode = EVP_aes_256_gcm();
            break;
        default:
            return 0;
            break;
    }
    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, CipherMode, NULL, reinterpret_cast<const unsigned char*>(Key.constData()), IV);
    unsigned char* CipherTxt = new unsigned char[Data.size()+16];
    int CipherSize;
    EVP_EncryptUpdate(ctx, CipherTxt, &CipherSize, reinterpret_cast<unsigned char*>(Data.data()), Data.size());
    EVP_EncryptFinal_ex(ctx, CipherTxt, &CipherSize);
    EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_GET_TAG, 16, &CipherTxt[Data.size()]);
    EVP_CIPHER_CTX_free(ctx);
    Result->append((const char*)IV,12);
    Result->append((const char*)CipherTxt,Data.size()+16);
    delete[] CipherTxt;
    return 1;
}
/*
 * Return Values:
 * 1 - Successful (GCM Tag is valid)
 * 0 - Successful (GCM Tag is not valid)
 * -1 - Invalid AES Key Size
 * -2 - Invaid Data Size
 */
int Encryption::IAES::Decrypt(QByteArray Key, QByteArray Data, QByteArray * Result) {
    const EVP_CIPHER * CipherMode;
    switch(Key.size()) {
        case 16:
            CipherMode = EVP_aes_128_gcm();
            break;
        case 24:
            CipherMode = EVP_aes_192_gcm();
            break;
        case 32:
            CipherMode = EVP_aes_256_gcm();
            break;
        default:
            return -1;
            break;
    }
    if(Data.size() < 28) {
        return -2;
    }
    QByteArray MainData = Data.mid(12,Data.size()-28);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, CipherMode, NULL, reinterpret_cast<const unsigned char*>(Key.constData()), reinterpret_cast<const unsigned char*>(Data.mid(0,12).data()));
    unsigned char* PlainTxt = new unsigned char[MainData.length()];
    int OutputLen;
    EVP_DecryptUpdate(ctx, PlainTxt, &OutputLen, reinterpret_cast<const unsigned char*>(MainData.data()), MainData.length());
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)Data.mid(Data.size()-16,16).data());
    int ResultValue = EVP_DecryptFinal_ex(ctx, PlainTxt, &OutputLen);
    EVP_CIPHER_CTX_free(ctx);
    Result->append(reinterpret_cast<char*>(PlainTxt),MainData.length());
    delete[] PlainTxt;
    return ResultValue;
}
/*
 * Return Values:
 * 1 - Successful
 * 0 - Invalid RSA Public Key
 * -1 - Invalid RSA Data size
 * -2 - PKEY CTX init failed
 * -3 - Padding Failed
 * -4 - Encryption Failed
 * -5 - Supplied key is not RSA
 */
int Encryption::IRSA::Encrypt(QByteArray IPubKey, QByteArray Data, QByteArray * Result) {
    BIO* PubKeyBio = BIO_new(BIO_s_mem());
    BIO_write(PubKeyBio,IPubKey.constData(),IPubKey.size());

    // Import RSA Key
    EVP_PKEY * PubKey = PEM_read_bio_PUBKEY(PubKeyBio,NULL,NULL,NULL);
    BIO_free_all(PubKeyBio);
    if(PubKey == NULL) return 0;

    // Check to ensure the key is RSA (ECC support is pending...)
    if(EVP_PKEY_base_id(PubKey) != EVP_PKEY_RSA)
        return -5;

    // Check RSA Key Size
    BIGNUM *bn = NULL;
    if(!EVP_PKEY_get_bn_param(PubKey, "n", &bn))
        return 0;
    if(Data.size() > BN_num_bytes(bn)-42) {
        EVP_PKEY_free(PubKey);
        BN_free(bn);
        return -1;
    }
    BN_free(bn);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(PubKey,NULL);
    if(EVP_PKEY_encrypt_init(ctx) <=0) {
        EVP_PKEY_free(PubKey);
        EVP_PKEY_CTX_free(ctx);
        return -2;
    }
    if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <=0) {
        EVP_PKEY_free(PubKey);
        EVP_PKEY_CTX_free(ctx);
        return -3;
    }
    size_t OutSize;
    EVP_PKEY_encrypt(ctx, NULL, &OutSize, (const unsigned char*)Data.constData(),Data.size());
    unsigned char* CipherText = new unsigned char[OutSize];
    if(EVP_PKEY_encrypt(ctx,CipherText,&OutSize, (const unsigned char*)Data.constData(),Data.size()) <=0) {
        EVP_PKEY_free(PubKey);
        EVP_PKEY_CTX_free(ctx);
        delete[] CipherText;
        return -4;
    }
    Result->append((const char*)CipherText,OutSize);
    EVP_PKEY_free(PubKey);
    EVP_PKEY_CTX_free(ctx);
    delete[] CipherText;
    return 1;
}
/*
 * Return Values:
 * 1 - Successful
 * 0 - Invalid RSA Key
 * -1 - Invalid data size
 * -2 - PKEY CTX init failed
 * -3 - Padding Failed
 * -4 - Decryption Failed
 * -5 - Supplied key is not RSA
 */
int Encryption::IRSA::Decrypt(QByteArray IPriKey, QByteArray Data, QByteArray * Result) {
    BIO* PriKeyBio = BIO_new(BIO_s_mem());
    BIO_write(PriKeyBio,IPriKey.constData(),IPriKey.size());

    // Read private key
    EVP_PKEY * PriKey = PEM_read_bio_PrivateKey(PriKeyBio,NULL,NULL,const_cast<char*>(""));
    BIO_free_all(PriKeyBio);
    if(PriKey == NULL) return 0;

    // Check to ensure the key is RSA (ECC support is pending...)
    if(EVP_PKEY_base_id(PriKey) != EVP_PKEY_RSA)
        return -5;

    // Check RSA Key Size
    BIGNUM *bn = NULL;
    if(!EVP_PKEY_get_bn_param(PriKey, "n", &bn))
        return 0;
    if(Data.size() > BN_num_bytes(bn)) {
        EVP_PKEY_free(PriKey);
        BN_free(bn);
        return -1;
    }
    BN_free(bn);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(PriKey,NULL);
    if(EVP_PKEY_decrypt_init(ctx) <=0) {
        EVP_PKEY_free(PriKey);
        EVP_PKEY_CTX_free(ctx);
        return -2;
    }
    if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <=0) {
        EVP_PKEY_free(PriKey);
        EVP_PKEY_CTX_free(ctx);

        return -3;
    }
    size_t OutSize;
    EVP_PKEY_decrypt(ctx, NULL, &OutSize, (const unsigned char*)Data.constData(),Data.size());
    unsigned char* PlainText = new unsigned char[OutSize];
    if(EVP_PKEY_decrypt(ctx,PlainText,&OutSize, (const unsigned char*)Data.constData(),Data.size()) <=0) {
        EVP_PKEY_free(PriKey);
        EVP_PKEY_CTX_free(ctx);
        delete[] PlainText;
        return -4;
    }
    Result->append((const char*)PlainText,OutSize);
    EVP_PKEY_free(PriKey);
    EVP_PKEY_CTX_free(ctx);
    delete[] PlainText;
    return 1;
}
/*
 * Return Values:
 * Dynamic - RSA Key Size
 * -1 - Invalid RSA Key
 * -2 - Supplied Key is not RSA
 */
int Encryption::IRSA::KeySize(QByteArray RSAKey,bool isPublic) {
    BIO* RSAKeyBio = BIO_new(BIO_s_mem());
    BIO_write(RSAKeyBio,RSAKey.constData(),RSAKey.size());
    EVP_PKEY* RSAKeyRSA = NULL;
    if(isPublic)
        RSAKeyRSA = PEM_read_bio_PUBKEY(RSAKeyBio,NULL,NULL,NULL);
    else
        RSAKeyRSA = PEM_read_bio_PrivateKey(RSAKeyBio,NULL,NULL,const_cast<char*>(""));
    BIO_free_all(RSAKeyBio);
    if(RSAKeyRSA == NULL) return -1;

    if(EVP_PKEY_base_id(RSAKeyRSA) != EVP_PKEY_RSA)
        return -2;

    // Get key size
    BIGNUM *bn = NULL;
    if(!EVP_PKEY_get_bn_param(RSAKeyRSA, "n", &bn))
        return 0;
    EVP_PKEY_free(RSAKeyRSA);

    int keysize = BN_num_bytes(bn);
    BN_free(bn);
    return keysize;
}

/* Return Values:
 * 1 - success
 */
int Utils::SHA256(QByteArray * data) {
    unsigned char result[32];
    unsigned int len;
    const EVP_MD* EVP = EVP_sha256();
    EVP_MD_CTX* MDCTX = EVP_MD_CTX_new();
    EVP_DigestInit_ex(MDCTX, EVP, NULL);
    EVP_DigestUpdate(MDCTX, data->constData(), data->length());
    EVP_DigestFinal_ex(MDCTX, result, &len);
    EVP_MD_CTX_free(MDCTX);

    // Write Data
    data->clear();
    data->append((const char*)result, len);

    return 1;
}
