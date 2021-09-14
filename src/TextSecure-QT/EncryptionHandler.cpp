#include "EncryptionHandler.h"
#include <ctime>
#include <stdio.h>
#include <process.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

// Legacy function in-case we need it lol
std::string RandChar(const int len) {

    std::string tmp_s;
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    srand( (unsigned) time(NULL) * _getpid());

    tmp_s.reserve(len);

    for (int i = 0; i < len; ++i)
        tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];

    return tmp_s;

}

void RandByte(unsigned char* RandFilling,int size) {
    srand( (unsigned) time(NULL) * _getpid()*(rand()%255));
    for (int i=0;i<size;i++) {
        RandFilling[i] = (unsigned char) rand();
    }
}
/*
 * Return Values:
 * 1 - Successful
 * 0 - Invalid AES Key size
*/
int Encryption::IAES::Encrypt(QByteArray Key, QByteArray Data, QByteArray * Result) {
    unsigned char* IV = new unsigned char[12];
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
    delete[] IV;
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
    QByteArray MainData = Data.sliced(12,Data.size()-28);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, CipherMode, NULL, reinterpret_cast<const unsigned char*>(Key.constData()), reinterpret_cast<const unsigned char*>(Data.sliced(0,12).data()));
    unsigned char* PlainTxt = new unsigned char[MainData.length()];
    int OutputLen;
    EVP_DecryptUpdate(ctx, PlainTxt, &OutputLen, reinterpret_cast<const unsigned char*>(MainData.data()), MainData.length());
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)Data.sliced(Data.size()-16,16).data());
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
 */
int Encryption::IRSA::Encrypt(QByteArray IPubKey, QByteArray Data, QByteArray * Result) {
    BIO* PubKeyBio = BIO_new(BIO_s_mem());
    BIO_write(PubKeyBio,IPubKey.constData(),IPubKey.size());
    RSA* PubKeyRSA = PEM_read_bio_RSAPublicKey(PubKeyBio,NULL,NULL,NULL); //PEM_read_bio_PUBKEY(PubKeyBio,NULL,NULL,NULL);
    if(PubKeyRSA == NULL) {
        return 0;
    }
    if(Data.size() > RSA_size(PubKeyRSA)-42) {
        BIO_free_all(PubKeyBio);
        return -1;
    }
    EVP_PKEY * PubKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(PubKey, PubKeyRSA);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(PubKey,NULL);
    if(EVP_PKEY_encrypt_init(ctx) <=0) {

        EVP_PKEY_free(PubKey);
        BIO_free_all(PubKeyBio);
        EVP_PKEY_CTX_free(ctx);
        return -2;
    }
    if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <=0) {
        EVP_PKEY_free(PubKey);
        BIO_free_all(PubKeyBio);
        EVP_PKEY_CTX_free(ctx);
        return -3;
    }
    size_t OutSize;
    EVP_PKEY_encrypt(ctx, NULL, &OutSize, (const unsigned char*)Data.constData(),Data.size());
    unsigned char* CipherText = new unsigned char[OutSize];
    if(EVP_PKEY_encrypt(ctx,CipherText,&OutSize, (const unsigned char*)Data.constData(),Data.size()) <=0) {
        EVP_PKEY_free(PubKey);
        EVP_PKEY_CTX_free(ctx);
        BIO_free_all(PubKeyBio);
        delete[] CipherText;
        return -4;
    }
    Result->append((const char*)CipherText,OutSize);
    EVP_PKEY_free(PubKey);
    EVP_PKEY_CTX_free(ctx);
    BIO_free_all(PubKeyBio);
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
 */
int Encryption::IRSA::Decrypt(QByteArray IPriKey, QByteArray Data, QByteArray * Result) {
    BIO* PriKeyBio = BIO_new(BIO_s_mem());
    BIO_write(PriKeyBio,IPriKey.constData(),IPriKey.size());
    RSA* PriKeyRSA = PEM_read_bio_RSAPrivateKey(PriKeyBio,NULL,NULL,const_cast<char*>(""));
    if(PriKeyRSA == NULL) {
        BIO_free_all(PriKeyBio);
        return 0;
    }
    if(Data.size() != RSA_size(PriKeyRSA)) {
        BIO_free_all(PriKeyBio);
        return -1;
    }
    EVP_PKEY * PriKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(PriKey, PriKeyRSA);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(PriKey,NULL);
    if(EVP_PKEY_decrypt_init(ctx) <=0) {
        EVP_PKEY_free(PriKey);
        EVP_PKEY_CTX_free(ctx);
        BIO_free_all(PriKeyBio);
        return -2;
    }
    if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <=0) {
        EVP_PKEY_free(PriKey);
        EVP_PKEY_CTX_free(ctx);
        BIO_free_all(PriKeyBio);
        return -3;
    }
    size_t OutSize;
    EVP_PKEY_decrypt(ctx, NULL, &OutSize, (const unsigned char*)Data.constData(),Data.size());
    unsigned char* PlainText = new unsigned char[OutSize];
    if(EVP_PKEY_decrypt(ctx,PlainText,&OutSize, (const unsigned char*)Data.constData(),Data.size()) <=0) {
        EVP_PKEY_free(PriKey);
        EVP_PKEY_CTX_free(ctx);
        BIO_free_all(PriKeyBio);
        delete[] PlainText;
        return -4;
    }
    Result->append((const char*)PlainText,OutSize);
    EVP_PKEY_free(PriKey);
    EVP_PKEY_CTX_free(ctx);
    BIO_free_all(PriKeyBio);
    delete[] PlainText;
    return 1;
}
/*
 * Return Values:
 * Dynamic - RSA Key Size
 * -1 - Invalid RSA Key
 */
int Encryption::IRSA::KeySize(QByteArray RSAKey,bool isPublic) {
    BIO* RSAKeyBio = BIO_new(BIO_s_mem());
    BIO_write(RSAKeyBio,RSAKey.constData(),RSAKey.size());
    RSA* RSAKeyRSA;
    if(isPublic) {
        RSAKeyRSA = PEM_read_bio_RSAPublicKey(RSAKeyBio,NULL,NULL,NULL);
    } else {
        RSAKeyRSA = PEM_read_bio_RSAPrivateKey(RSAKeyBio,NULL,NULL,const_cast<char*>(""));
    }
    if(RSAKeyRSA == NULL) {
        // Not a private key? Then it an invalid key
        BIO_free_all(RSAKeyBio);
        return -1;
    }
    BIO_free_all(RSAKeyBio);
    int RSAKeySize = RSA_size(RSAKeyRSA);
    RSA_free(RSAKeyRSA);
    return RSAKeySize;
}
