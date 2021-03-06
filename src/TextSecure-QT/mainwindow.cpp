#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include "EncryptionHandler.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#ifdef _WIN64
// x64 bit Windows library
#include <process.h>
#elif __linux__ || __unix__
// x64 bit Linux library
#include <unistd.h>
#endif

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

bool is_number(const std::string& s)
{
    std::string::const_iterator it = s.begin();
    while (it != s.end() && std::isdigit(*it)) ++it;
    return !s.empty() && it == s.end();
}
void MainWindow::on_EncryptBtn_clicked()
{
    QMessageBox * msgbox = new QMessageBox(this);
    msgbox->setWindowTitle("AES Encryption");
    QByteArray * Result = new QByteArray();
    switch(Encryption::IAES::Encrypt(ui->KeyInput->text().toUtf8(),ui->EncInput->toPlainText().toUtf8(),Result)) {
    case 1:
        ui->EncOutput->setPlainText(Result->toBase64());
        ui->EncInput->setPlainText("");
        break;
    case 0:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Your AES key must be a 16, 24, or 32 bytes long. Current size: "+QString::number(ui->KeyInput->text().toUtf8().size()));
        msgbox->exec();
        break;
    default:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Something else went wrong");
        msgbox->exec();
        break;
    }
    delete Result;
    delete msgbox;
}


void MainWindow::on_DecryptBtn_clicked()
{
    QMessageBox * msgbox = new QMessageBox(this);
    msgbox->setWindowTitle("AES Encryption");
    QByteArray * Result = new QByteArray();
    switch(Encryption::IAES::Decrypt(ui->KeyInput->text().toUtf8(),QByteArray::fromBase64(ui->DecInput->toPlainText().toUtf8()),Result)) {
    case 1:
        ui->DecOutput->setPlainText(QString::fromUtf8(*Result));
        ui->MessageStatus->setText("Message is original: Yes");
        ui->DecInput->setPlainText("");
        break;
    case 0:
        ui->DecOutput->setPlainText(QString::fromUtf8(*Result));
        ui->MessageStatus->setText("Message is original: No");
        ui->DecInput->setPlainText("");
        break;
    case -1:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Your AES key must be a 16, 24, or 32 bytes long. Current size: "+QString::number(ui->KeyInput->text().toUtf8().size()));
        msgbox->exec();
        break;
   case -2:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Invalid input has been supplied");
        msgbox->exec();
        break;
   default:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Something else went wrong");
        msgbox->exec();
        break;

    }
    delete Result;
    delete msgbox;
}


void MainWindow::on_EncClear_clicked()
{
 switch(QMessageBox::question(this,"Clear Encryption Message","Are you sure that you want to clear your encrypted message?",QMessageBox::Yes | QMessageBox::No)) {
    case QMessageBox::Yes:
     // Yes Do it
     ui->EncOutput->setPlainText("");
     break;
    default:
     // Dont do it
     break;
 }
}


void MainWindow::on_DecClear_clicked()
{
    switch(QMessageBox::question(this,"Clear Decryption Message","Are you sure that you want to clear your decrypted message?",QMessageBox::Yes | QMessageBox::No)) {
       case QMessageBox::Yes:
        // Yes Do it
        ui->DecOutput->setPlainText("");
        ui->MessageStatus->setText("Message is original: NULL");
        break;
       default:
        // Dont do it
        break;
    }
}

void MainWindow::on_GenRSAKey_clicked()
{
    QMessageBox * msgbox = new QMessageBox(this);
    msgbox->setWindowTitle("RSA Key Generation");
    if(!is_number(ui->GenKeySize->text().toStdString())) {
        msgbox->setText("RSA key size input is not a valid number");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        delete msgbox;
        return;
    }
    int UserKeySize = std::stoi(ui->GenKeySize->text().toStdString());
    if(UserKeySize < 512) {
        msgbox->setText("RSA key size is too small. Minimum is 512. (512 size already vulnerable to be cracked so not sure why you want it any smaller)");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        delete msgbox;
        return;
    } else if(UserKeySize > 16384) {
        msgbox->setText("RSA key size is too big. Maximum size is 16384. (Why do you need such as big size key. 2048 is already enough and some software doesn't support big key sizes)");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        delete msgbox;
        return;
    }
    RSA* RSAData = RSA_new();
    BIGNUM * BigNum = BN_new();
    BN_set_word(BigNum, RSA_F4);
    if(RSA_generate_key_ex(RSAData,UserKeySize,BigNum,NULL) == 0) {
        msgbox->setText("RSA Key has failed to generate, please try again");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        BN_free(BigNum);
        //RSA_free(RSAData);
        delete msgbox;
        return;
    }

    EVP_PKEY * RSAKey = EVP_PKEY_new();
    if(EVP_PKEY_assign_RSA(RSAKey, RSAData) == 0) {
        msgbox->setText("Key Assignment Failed");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        EVP_PKEY_free(RSAKey);
        BN_free(BigNum);
        //RSA_free(RSAData);
        delete msgbox;
        return;
    }
    BIO* PriKeyBio = BIO_new(BIO_s_mem());
    if(PEM_write_bio_PKCS8PrivateKey(PriKeyBio, RSAKey,NULL,NULL,0,NULL,NULL) == 0) {
        msgbox->setText("Failed To Export Private Key");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        EVP_PKEY_free(RSAKey);
        BN_free(BigNum);
        delete msgbox;
        BIO_free_all(PriKeyBio);
        //RSA_free(RSAData);
        return;
    }
    BIO* PubKeyBio = BIO_new(BIO_s_mem());
    if(PEM_write_bio_RSAPublicKey(PubKeyBio,RSAData) == 0) {
        msgbox->setText("Failed To Export Public Key");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        EVP_PKEY_free(RSAKey);
        BN_free(BigNum);
        delete msgbox;
        BIO_free_all(PriKeyBio);
        BIO_free_all(PubKeyBio);
        //RSA_free(RSAData);
        return;
    }
    BUF_MEM *PriKey;
    BUF_MEM *PubKey;
    BIO_get_mem_ptr(PriKeyBio, &PriKey);
    BIO_get_mem_ptr(PubKeyBio, &PubKey);
    ui->PrivateKeyInput->setPlainText(QString::fromUtf8(PriKey->data,PriKey->length));
    ui->PublicKeyInput->setPlainText(QString::fromUtf8(PubKey->data,PubKey->length));
    msgbox->setText("RSA Key has been successfully generated");
    msgbox->setIcon(QMessageBox::Icon::Information);
    msgbox->exec();
    EVP_PKEY_free(RSAKey);
    BN_free(BigNum);
    BIO_free_all(PriKeyBio);
    BIO_free_all(PubKeyBio);
    //RSA_free(RSAData);
    delete msgbox;

}


void MainWindow::on_REncryptBtn_clicked()
{
    QMessageBox * msgbox = new QMessageBox(this);
    msgbox->setWindowTitle("RSA Encryption");
    QByteArray * Result = new QByteArray();
    switch(Encryption::IRSA::Encrypt(ui->PublicKeyInput->toPlainText().toUtf8(),ui->REncInput->toPlainText().toUtf8(),Result)) {
    case 1:
        ui->REncOutput->setPlainText(Result->toBase64());
        ui->REncInput->setPlainText("");
        break;
    case 0:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Invalid Public RSA Key has been detected");
        msgbox->exec();
        break;
    case -1:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Your message is too long for your key size, please reduce it");
        msgbox->exec();
        break;
   case -4:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("RSA was unable to encrypt your message");
        msgbox->exec();
        break;
   default:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Something else went wrong");
        msgbox->exec();
        break;

    }
    delete Result;
    delete msgbox;
}


void MainWindow::on_RDecryptBtn_clicked()
{
    QMessageBox * msgbox = new QMessageBox(this);
    msgbox->setWindowTitle("RSA Encryption");
    QByteArray * Result = new QByteArray();
    switch(Encryption::IRSA::Decrypt(ui->PrivateKeyInput->toPlainText().toUtf8(),QByteArray::fromBase64(ui->RDecInput->toPlainText().toUtf8()),Result)) {
    case 1:
        ui->RDecOutput->setPlainText(*Result);
        ui->RDecInput->setPlainText("");
        break;
    case 0:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Invalid Private RSA Key has been detected");
        msgbox->exec();
        break;
    case -1:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Invalid input has been supplied");
        msgbox->exec();
        break;
   case -4:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("RSA was unable to decrypt your message");
        msgbox->exec();
        break;
   default:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Something else went wrong");
        msgbox->exec();
        break;

    }
    delete Result;
    delete msgbox;
}


void MainWindow::on_REncryptClear_clicked()
{
    switch(QMessageBox::question(this,"Clear Encryption Message","Are you sure that you want to clear your encrypted message?",QMessageBox::Yes | QMessageBox::No)) {
       case QMessageBox::Yes:
        // Yes Do it
        ui->REncOutput->setPlainText("");
        break;
       default:
        // Dont do it
        break;
    }
}


void MainWindow::on_RDecryptClear_clicked()
{
    switch(QMessageBox::question(this,"Clear Decryption Message","Are you sure that you want to clear your decrypted message?",QMessageBox::Yes | QMessageBox::No)) {
       case QMessageBox::Yes:
        // Yes Do it
        ui->RDecOutput->setPlainText("");
        break;
       default:
        // Dont do it
        break;
    }
}


void MainWindow::on_PriToPubKeyBtn_clicked()
{
    QMessageBox *msgbox = new QMessageBox(this);
    msgbox->setWindowTitle("Key Converter");
    BIO* PriKeyBio = BIO_new(BIO_s_mem());
    BIO_write(PriKeyBio,ui->PrivateKeyInput->toPlainText().toStdString().c_str(),ui->PrivateKeyInput->toPlainText().toUtf8().size());
    RSA* PriKeyRSA = PEM_read_bio_RSAPrivateKey(PriKeyBio,NULL,NULL,const_cast<char*>(""));
    BIO* PubKeyBio = BIO_new(BIO_s_mem());
    if(PEM_write_bio_RSAPublicKey(PubKeyBio,PriKeyRSA) <= 0) {
        msgbox->setText("Failed To Convert Private Key To Public Key");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        delete msgbox;
        BIO_free_all(PriKeyBio);
        BIO_free_all(PubKeyBio);
        //RSA_free(RSAData);
        return;
    }
    BUF_MEM *PubKey;
    BIO_get_mem_ptr(PubKeyBio, &PubKey);
    ui->PublicKeyInput->setPlainText(QString::fromUtf8(PubKey->data,PubKey->length));
    msgbox->setIcon(QMessageBox::Icon::Information);
    msgbox->setText("Successfully extract public key from private key");
    msgbox->exec();
    delete msgbox;
    BIO_free_all(PriKeyBio);
    BIO_free_all(PubKeyBio);
}


void MainWindow::on_ImportPubCert_clicked()
{
    QMessageBox *msgbox = new QMessageBox(this);
    msgbox->setWindowTitle("Key Converter");
    BIO* CertKeyBio = BIO_new(BIO_s_mem());
    BIO_write(CertKeyBio,ui->PublicCertInput->toPlainText().toStdString().c_str(),ui->PublicCertInput->toPlainText().toUtf8().size());
    X509 * PubCert = PEM_read_bio_X509(CertKeyBio,NULL,NULL,NULL);
    EVP_PKEY * PubKeyObj = X509_get_pubkey(PubCert);
    BUF_MEM *PubKey;
    BIO* PubKeyBio = BIO_new(BIO_s_mem());
    if(PubKeyObj == NULL) {
        msgbox->setText("Invalid Certificate was provided");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        delete msgbox;
        return;
    }
    RSA* PubKeyRSA = EVP_PKEY_get1_RSA(PubKeyObj);
    if(PEM_write_bio_RSAPublicKey(PubKeyBio,PubKeyRSA)  <= 0) {
        msgbox->setText("Unable to convert certificate to public key");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        delete msgbox;
        return;
    }

    BIO_get_mem_ptr(PubKeyBio, &PubKey);
    ui->PublicKeyInput->setPlainText(QString::fromUtf8(PubKey->data,PubKey->length));
    ui->PublicCertInput->setPlainText("");
    BIO_free_all(CertKeyBio);
    BIO_free_all(PubKeyBio);
    X509_free(PubCert);
    msgbox->setText("Successfully converted public certificate to public key");
    msgbox->setIcon(QMessageBox::Icon::Information);
    msgbox->exec();
    delete msgbox;
}
int cb(char *buf, int size, int rwflag, void *u);

void MainWindow::on_PriKeyEncBtn_clicked()
{
    QMessageBox *msgbox = new QMessageBox(this);
    msgbox->setWindowTitle("Key Encryptor");
    BIO* PriKeyBio = BIO_new(BIO_s_mem());
    BIO_write(PriKeyBio,ui->PrivateKeyInput->toPlainText().toStdString().c_str(),ui->PrivateKeyInput->toPlainText().toUtf8().size());

    RSA* PriKeyRSA = PEM_read_bio_RSAPrivateKey(PriKeyBio,NULL,NULL,const_cast<char*>(""));
    BIO* EncPriKeyBio = BIO_new(BIO_s_mem());
    EVP_PKEY * RSAKey = EVP_PKEY_new();
    if(EVP_PKEY_assign_RSA(RSAKey, PriKeyRSA) <= 0) {
        msgbox->setText("Invalid RSA Private key was provided or you're trying to encrypt an already encrypted key");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        EVP_PKEY_free(RSAKey);
        //RSA_free(RSAData);
        delete msgbox;
        return;
    }
    if(PEM_write_bio_PKCS8PrivateKey(EncPriKeyBio,RSAKey,EVP_des_ede3_cbc(),NULL,0,0,ui->PriKeyPassInput->text().toUtf8().data()) <= 0) {
        msgbox->setText("Failed To Encrypt Private Key or you forgot to set a passphrase");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        delete msgbox;
        BIO_free_all(PriKeyBio);
        BIO_free_all(EncPriKeyBio);
        //RSA_free(RSAData);
        return;
    }
    BUF_MEM *EncPriKey;
    BIO_get_mem_ptr(EncPriKeyBio, &EncPriKey);
    ui->PrivateKeyInput->setPlainText(QString::fromUtf8(EncPriKey->data,EncPriKey->length));
    ui->PriKeyPassInput->setText("");
    msgbox->setIcon(QMessageBox::Icon::Information);
    msgbox->setText("Successfully encrypted your private key");
    msgbox->exec();
    delete msgbox;
    BIO_free_all(PriKeyBio);
    BIO_free_all(EncPriKeyBio);
}


void MainWindow::on_PriKeyDecBtn_clicked()
{
    QMessageBox *msgbox = new QMessageBox(this);
    msgbox->setWindowTitle("Key Encryptor");
    BIO* PriKeyBio = BIO_new(BIO_s_mem());
    BIO_write(PriKeyBio,ui->PrivateKeyInput->toPlainText().toStdString().c_str(),ui->PrivateKeyInput->toPlainText().toUtf8().size());
    RSA* PriKeyRSA = PEM_read_bio_RSAPrivateKey(PriKeyBio,NULL,0,ui->PriKeyPassInput->text().toUtf8().data());
    BIO* EncPriKeyBio = BIO_new(BIO_s_mem());
    EVP_PKEY * RSAKey = EVP_PKEY_new();
    if(EVP_PKEY_assign_RSA(RSAKey, PriKeyRSA) <= 0) {
        msgbox->setText("Invalid Private Key or Passphrase");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        EVP_PKEY_free(RSAKey);
        //RSA_free(RSAData);
        delete msgbox;
        return;
    }
    if(PEM_write_bio_PKCS8PrivateKey(EncPriKeyBio,RSAKey,NULL,NULL,0,NULL,NULL) <= 0) {
        msgbox->setText("Failed To Decrypt Private Key");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        delete msgbox;
        BIO_free_all(PriKeyBio);
        BIO_free_all(EncPriKeyBio);
        //RSA_free(RSAData);
        return;
    }
    BUF_MEM *EncPriKey;
    BIO_get_mem_ptr(EncPriKeyBio, &EncPriKey);
    ui->PrivateKeyInput->setPlainText(QString::fromUtf8(EncPriKey->data,EncPriKey->length));
    ui->PriKeyPassInput->setText("");
    msgbox->setIcon(QMessageBox::Icon::Information);
    msgbox->setText("Successfully decrypted your private key");
    msgbox->exec();
    delete msgbox;
    BIO_free_all(PriKeyBio);
    BIO_free_all(EncPriKeyBio);
}

void MainWindow::on_AREncryptBtn_clicked()
{
    QMessageBox * msgbox = new QMessageBox(this);
    msgbox->setWindowTitle("AES/RSA Encryption");
    unsigned char* RandKey;
    int KeySize = 0;
    if((Encryption::IRSA::KeySize(ui->PublicKeyInput->toPlainText().toUtf8(),true)/8)-42 < 32) {
        RandKey = new unsigned char[16];
        KeySize = 16;
    } else {
        RandKey = new unsigned char[32];
        KeySize = 32;
    }
#ifdef _WIN64
// x64 bit Windows library
srand( (unsigned) time(NULL) * _getpid()*(rand()%255));
#elif __linux__ || __unix__
// x64 bit Linux library
srand( (unsigned) time(NULL) * getpid()*(rand()%255));
#endif
    for (int i=0;i<KeySize;i++) {
        RandKey[i] = (unsigned char) rand();
    }
    QByteArray * EncryptedAESKey = new QByteArray();
    switch(Encryption::IRSA::Encrypt(ui->PublicKeyInput->toPlainText().toUtf8(),QByteArray::fromRawData((const char*)RandKey,KeySize),EncryptedAESKey)) {
    case 1:
        break;
    case 0:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Invalid Public RSA Key has been detected");
        msgbox->exec();
        delete EncryptedAESKey;
        delete RandKey;
        delete msgbox;
        return;
   case -4:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Unable to encrypt your AES Key");
        msgbox->exec();
        delete EncryptedAESKey;
        delete RandKey;
        delete msgbox;
        return;
   default:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Something else went wrong");
        msgbox->exec();
        delete EncryptedAESKey;
        delete RandKey;
        delete msgbox;
        return;
    }
    QByteArray * EncData = new QByteArray();
    EncData->append(*EncryptedAESKey);
    switch(Encryption::IAES::Encrypt(QByteArray::fromRawData((const char*)RandKey,KeySize),ui->AREncInput->toPlainText().toUtf8(),EncData)) {
    case 1:
        ui->AREncOutput->setPlainText(EncData->toBase64());
        ui->AREncInput->setPlainText("");
        break;
   default:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Something else went wrong");
        msgbox->exec();
        delete EncryptedAESKey;
        delete RandKey;
        delete msgbox;
        return;
    }
    delete EncryptedAESKey;
    delete EncData;
    delete RandKey;
    delete msgbox;
}

void MainWindow::on_ARDecryptBtn_clicked()
{
    QMessageBox * msgbox = new QMessageBox(this);
    msgbox->setWindowTitle("AES/RSA Decryption");
    QByteArray * DecryptedAESKey = new QByteArray();
    int RSAKeyLen = Encryption::IRSA::KeySize(ui->PrivateKeyInput->toPlainText().toUtf8(),false);
    QByteArray MainData = QByteArray::fromBase64(ui->ARDecInput->toPlainText().toUtf8());
    if(RSAKeyLen <= 0) {
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Invalid Private RSA Key has been detected");
        msgbox->exec();
        delete DecryptedAESKey;
        delete msgbox;
        return;
    }else if(MainData.size() < RSAKeyLen+28) {
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Invalid input has been supplied");
        msgbox->exec();
        delete DecryptedAESKey;
        delete msgbox;
        return;
    }
    switch(Encryption::IRSA::Decrypt(ui->PrivateKeyInput->toPlainText().toUtf8(),MainData.mid(0,RSAKeyLen),DecryptedAESKey)) {
    case 1:
        break;
    case 0:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Invalid RSA Private Key has been detected");
        msgbox->exec();
        delete DecryptedAESKey;
        delete msgbox;
        return;
   case -4:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Unable to decrypt your AES Key");
        msgbox->exec();
        delete DecryptedAESKey;
        delete msgbox;
        return;
   default:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Something else went wrong");
        msgbox->exec();
        delete DecryptedAESKey;
        delete msgbox;
        return;
    }

    QByteArray * DecData = new QByteArray();
    switch(Encryption::IAES::Decrypt(*DecryptedAESKey,MainData.mid(RSAKeyLen,MainData.size()-RSAKeyLen),DecData)) {
    case 1:
        ui->ARMessageStatus->setText("Message is original: Yes");
        ui->ARDecOutput->setPlainText(*DecData);
        ui->ARDecInput->setPlainText("");
        break;
    case 0:
        ui->ARMessageStatus->setText("Message is original: Yes");
        ui->ARDecOutput->setPlainText(*DecData);
        ui->ARDecInput->setPlainText("");
        break;
   default:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Something else went wrong");
        msgbox->exec();
        break;
    }
    delete DecryptedAESKey;
    delete DecData;
    delete msgbox;
}


void MainWindow::on_AREncryptClear_clicked()
{
    switch(QMessageBox::question(this,"Clear Encryption Message","Are you sure that you want to clear your encrypted message?",QMessageBox::Yes | QMessageBox::No)) {
       case QMessageBox::Yes:
        // Yes Do it
        ui->AREncOutput->setPlainText("");
        break;
       default:
        // Dont do it
        break;
    }
}


void MainWindow::on_ARDecryptClear_clicked()
{
    switch(QMessageBox::question(this,"Clear Decryption Message","Are you sure that you want to clear your decrypted message?",QMessageBox::Yes | QMessageBox::No)) {
       case QMessageBox::Yes:
        // Yes Do it
        ui->ARDecOutput->setPlainText("");
        ui->ARMessageStatus->setText("Message is original: NULL");
        break;
       default:
        // Dont do it
        break;
    }
}

