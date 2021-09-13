#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <ctime>
#include <stdio.h>
#include <process.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>


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
const EVP_CIPHER * CheckKeyLen(QWidget *parent,QString UserInput) {
    switch(UserInput.toUtf8().size()) {
        case 16:
             return EVP_aes_128_gcm();
        case 24:
            return EVP_aes_192_gcm();
        case 32:
            return EVP_aes_256_gcm();
        default:
            QMessageBox * msg = new QMessageBox(parent);
            msg->setWindowTitle("Invalid Key Length");
            msg->setIcon(QMessageBox::Icon::Critical);
            msg->setText("Invalid Key Length, must be 16, 24, or 32 characters long. Your Key's byte size: "+QString::fromStdString(std::to_string(UserInput.toUtf8().size())));
            msg->exec();
            delete msg;
            msg = nullptr;
           return NULL;
    }
}
bool is_number(const std::string& s)
{
    std::string::const_iterator it = s.begin();
    while (it != s.end() && std::isdigit(*it)) ++it;
    return !s.empty() && it == s.end();
}
void MainWindow::on_EncryptBtn_clicked()
{
    unsigned char* IV = new unsigned char[12];
    RandByte(IV,12);
    const EVP_CIPHER * CipherMode = CheckKeyLen(this,ui->KeyInput->text());
    if(CipherMode == NULL) {
        return;
    }
    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, CipherMode, NULL, reinterpret_cast<const unsigned char*>(ui->KeyInput->text().constData()), IV);
    unsigned char* CipherTxt = new unsigned char[strlen(ui->EncInput->toPlainText().toStdString().c_str())+16];
    int CipherSize;
    EVP_EncryptUpdate(ctx, CipherTxt, &CipherSize, (unsigned char*)ui->EncInput->toPlainText().toStdString().c_str(), strlen(ui->EncInput->toPlainText().toStdString().c_str()));
    EVP_EncryptFinal_ex(ctx, CipherTxt, &CipherSize);
    EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_GET_TAG, 16, &CipherTxt[strlen(ui->EncInput->toPlainText().toStdString().c_str())]);
    EVP_CIPHER_CTX_free(ctx);
    QByteArray * Data = new QByteArray((const char*)IV,12);
    Data->append((const char*)CipherTxt,strlen(ui->EncInput->toPlainText().toStdString().c_str())+16);
    ui->EncOutput->setPlainText(Data->toBase64());
    //ui->EncOutput->setText((const char*)CipherTxt);
    ui->EncInput->setPlainText("");
    delete Data;
    delete[] CipherTxt;
}


void MainWindow::on_DecryptBtn_clicked()
{
    QString MsgTampDisPrefix = "Message is original: ";
    const EVP_CIPHER * CipherMode = CheckKeyLen(this,ui->KeyInput->text());
    if(CipherMode == NULL) {
        return;
    }
    QByteArray DataByte = QByteArray::fromBase64(ui->DecInput->toPlainText().toUtf8());
    if(DataByte.size() < 28) {
        QMessageBox * msg = new QMessageBox();
        msg->setWindowTitle("Invalid Message");
        msg->setText("Invalid input has been supplied");
        msg->setIcon(QMessageBox::Critical);
        msg->exec();
        delete msg;
        return;
    }
    QByteArray IV = DataByte.sliced(0,12);
    QByteArray MainData = DataByte.sliced(12,DataByte.size()-28);
    QByteArray MainTag = DataByte.sliced(DataByte.size()-16,16);
    /*
    qDebug() << strlen(IV);
    qDebug() << strlen(MainData);
    qDebug() << strlen(MainTag);
    */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, CipherMode, NULL, reinterpret_cast<const unsigned char*>(ui->KeyInput->text().constData()), reinterpret_cast<const unsigned char*>(IV.data()));
    unsigned char* PlainTxt = new unsigned char[MainData.length()];
    int OutputLen;
    EVP_DecryptUpdate(ctx, PlainTxt, &OutputLen, reinterpret_cast<const unsigned char*>(MainData.data()), MainData.length());
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)MainTag.data());
    switch(EVP_DecryptFinal_ex(ctx, PlainTxt, &OutputLen)) {
        case 1:
            // Decryption Correct
            ui->MessageStatus->setText(MsgTampDisPrefix+"Yes");
            break;
        case 0:
            // Decryption Bad
            ui->MessageStatus->setText(MsgTampDisPrefix+"No");
            break;
        default:
            // Bad Result
            ui->MessageStatus->setText(MsgTampDisPrefix+"Unknown");
            break;
    }
      EVP_CIPHER_CTX_free(ctx);
     //qDebug() << QString::fromUtf8(PlainTxt).size();
    ui->DecOutput->setPlainText(QString::fromUtf8(reinterpret_cast<char*>(PlainTxt),MainData.length()));
    ui->DecInput->setPlainText("");
    delete[] PlainTxt;
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
    QMessageBox msgbox;
    msgbox.setWindowTitle("RSA Encryption");
    BIO* PubKeyBio = BIO_new(BIO_s_mem());
    BIO_write(PubKeyBio,ui->PublicKeyInput->toPlainText().toStdString().c_str(),ui->PublicKeyInput->toPlainText().toUtf8().size());
    //BIO* PubKeyBio = BIO_new_mem_buf(ui->PublicKeyInput->toPlainText().toStdString().c_str(),ui->PublicKeyInput->toPlainText().toUtf8().size());
    RSA* PubKeyRSA = PEM_read_bio_RSAPublicKey(PubKeyBio,NULL,NULL,NULL); //PEM_read_bio_PUBKEY(PubKeyBio,NULL,NULL,NULL);
    QString Qdata = ui->REncInput->toPlainText();
    if(PubKeyRSA == NULL) {
        msgbox.setIcon(QMessageBox::Icon::Critical);
        msgbox.setText("Invalid RSA Public key was provided");
        msgbox.exec();
        BIO_free_all(PubKeyBio);
        return;
    }
    if(Qdata.toUtf8().size() > RSA_size(PubKeyRSA)-42) {
        msgbox.setIcon(QMessageBox::Icon::Critical);
        msgbox.setText("Message to big for your current key size. Maximum message byte: "+QString::number(RSA_size(PubKeyRSA)-42));
        msgbox.exec();
        BIO_free_all(PubKeyBio);
        return;
    }
    EVP_PKEY * PubKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(PubKey, PubKeyRSA);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(PubKey,NULL);
    if(EVP_PKEY_encrypt_init(ctx) <=0) {
        msgbox.setIcon(QMessageBox::Icon::Critical);
        msgbox.setText("Init failed");
        msgbox.exec();
        EVP_PKEY_free(PubKey);
        BIO_free_all(PubKeyBio);
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <=0) {
        msgbox.setIcon(QMessageBox::Icon::Critical);
        msgbox.setText("Padding Mode Failed");
        msgbox.exec();
        EVP_PKEY_free(PubKey);
        BIO_free_all(PubKeyBio);
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    size_t OutSize;
    EVP_PKEY_encrypt(ctx, NULL, &OutSize, (const unsigned char*)Qdata.toStdString().c_str(),Qdata.toUtf8().size());
    unsigned char* CipherText = new unsigned char[OutSize];
    if(EVP_PKEY_encrypt(ctx,CipherText,&OutSize, (const unsigned char*)Qdata.toStdString().c_str(),Qdata.toUtf8().size()) <=0) {
        msgbox.setIcon(QMessageBox::Icon::Critical);
        msgbox.setText("Encryption Mode Failed");
        msgbox.exec();
        EVP_PKEY_free(PubKey);
        EVP_PKEY_CTX_free(ctx);
        BIO_free_all(PubKeyBio);
        delete[] CipherText;
        return;
    }
    ui->REncOutput->setPlainText(QByteArray::fromRawData((const char*)CipherText,OutSize).toBase64());
    ui->REncInput->setPlainText("");
    EVP_PKEY_free(PubKey);
    EVP_PKEY_CTX_free(ctx);
    BIO_free_all(PubKeyBio);
    delete[] CipherText;
    /*
    */
}


void MainWindow::on_RDecryptBtn_clicked()
{
    QMessageBox msgbox;
    msgbox.setWindowTitle("RSA Decryption");
    QByteArray Qdata = QByteArray::fromBase64(ui->RDecInput->toPlainText().toUtf8());
    BIO* PriKeyBio = BIO_new(BIO_s_mem());
    BIO_write(PriKeyBio,ui->PrivateKeyInput->toPlainText().toStdString().c_str(),ui->PrivateKeyInput->toPlainText().toUtf8().size());
    RSA* PriKeyRSA = PEM_read_bio_RSAPrivateKey(PriKeyBio,NULL,NULL,const_cast<char*>(""));
    if(PriKeyRSA == NULL) {
        msgbox.setIcon(QMessageBox::Icon::Critical);
        msgbox.setText("Invalid RSA Private key was provided or the key isn't decrypted");
        msgbox.exec();
        BIO_free_all(PriKeyBio);
        return;
    }
    if(Qdata.size() != RSA_size(PriKeyRSA)) {
        msgbox.setIcon(QMessageBox::Icon::Critical);
        msgbox.setText("Invalid input has been supplied");
        msgbox.exec();
        BIO_free_all(PriKeyBio);
        return;
    }
    EVP_PKEY * PriKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(PriKey, PriKeyRSA);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(PriKey,NULL);
    if(EVP_PKEY_decrypt_init(ctx) <=0) {
        msgbox.setIcon(QMessageBox::Icon::Critical);
        msgbox.setText("Init failed");
        msgbox.exec();
        EVP_PKEY_free(PriKey);
        EVP_PKEY_CTX_free(ctx);
        BIO_free_all(PriKeyBio);
        return;
    }
    if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <=0) {
        msgbox.setIcon(QMessageBox::Icon::Critical);
        msgbox.setText("Padding Mode Failed");
        msgbox.exec();
        EVP_PKEY_free(PriKey);
        EVP_PKEY_CTX_free(ctx);
        BIO_free_all(PriKeyBio);
        return;
    }
    size_t OutSize;
    EVP_PKEY_decrypt(ctx, NULL, &OutSize, (const unsigned char*)Qdata.constData(),Qdata.size());
    unsigned char* PlainText = new unsigned char[OutSize];
    if(EVP_PKEY_decrypt(ctx,PlainText,&OutSize, (const unsigned char*)Qdata.constData(),Qdata.size()) <=0) {
        msgbox.setIcon(QMessageBox::Icon::Critical);
        msgbox.setText("Decryption Mode Failed");
        msgbox.exec();
        EVP_PKEY_free(PriKey);
        EVP_PKEY_CTX_free(ctx);
        BIO_free_all(PriKeyBio);
        delete[] PlainText;
        return;
    }
    ui->RDecOutput->setPlainText(QByteArray::fromRawData((const char*)PlainText,OutSize));
    ui->RDecInput->setPlainText("");
    EVP_PKEY_free(PriKey);
    EVP_PKEY_CTX_free(ctx);
    BIO_free_all(PriKeyBio);
    delete[] PlainText;
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
    QMessageBox msgbox;
    BIO* PubKeyBio = BIO_new(BIO_s_mem());
    BIO_write(PubKeyBio,ui->PublicKeyInput->toPlainText().toStdString().c_str(),ui->PublicKeyInput->toPlainText().toUtf8().size());
    RSA* PubKeyRSA = PEM_read_bio_RSAPublicKey(PubKeyBio,NULL,NULL,NULL);
    if(PubKeyRSA == NULL) {
        msgbox.setIcon(QMessageBox::Icon::Critical);
        msgbox.setText("Invalid RSA Public key was provided");
        msgbox.exec();
        BIO_free_all(PubKeyBio);
        return;
    }
    unsigned char* RandKey;
    unsigned char* RandIV = new unsigned char[12];
    QByteArray UserData = ui->AREncInput->toPlainText().toUtf8();
    EVP_PKEY * PubKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(PubKey, PubKeyRSA);
    RandByte(RandIV,12);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(PubKey,NULL);
    if(EVP_PKEY_encrypt_init(ctx) <=0) {
        msgbox.setIcon(QMessageBox::Icon::Critical);
        msgbox.setText("Init failed");
        msgbox.exec();
        EVP_PKEY_free(PubKey);
        BIO_free_all(PubKeyBio);
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <=0) {
        msgbox.setIcon(QMessageBox::Icon::Critical);
        msgbox.setText("Padding Mode Failed");
        msgbox.exec();
        EVP_PKEY_free(PubKey);
        BIO_free_all(PubKeyBio);
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    const EVP_CIPHER * CipherMode;
    int keysize = 0;
    if((RSA_size(PubKeyRSA)/8)-42 < 32) {
        RandKey = new unsigned char[16];
        RandByte(RandKey,16);
        keysize = 16;
        CipherMode = EVP_aes_128_gcm();
    } else {
        RandKey = new unsigned char[32];
        RandByte(RandKey,32);
        keysize = 32;
        CipherMode = EVP_aes_256_gcm();
    }
    size_t OutputSize;
    EVP_PKEY_encrypt(ctx, NULL, &OutputSize, RandKey,keysize);
    unsigned char * CipherKey = new unsigned char[OutputSize];
    if(EVP_PKEY_encrypt(ctx,CipherKey,&OutputSize, RandKey,keysize) <=0) {
        msgbox.setIcon(QMessageBox::Icon::Critical);
        msgbox.setText("Encryption Mode Failed");
        msgbox.exec();
        EVP_PKEY_free(PubKey);
        EVP_PKEY_CTX_free(ctx);
        BIO_free_all(PubKeyBio);
        delete[] CipherKey;
        return;
    }
    EVP_CIPHER_CTX * aesctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(aesctx, CipherMode, NULL, RandKey, RandIV);
    unsigned char* CipherTxt = new unsigned char[UserData.size()+16];
    int CipherSize;
    EVP_EncryptUpdate(aesctx, CipherTxt, &CipherSize, (unsigned char*)ui->AREncInput->toPlainText().toStdString().c_str(), UserData.size());
    EVP_EncryptFinal_ex(aesctx, CipherTxt, &CipherSize);
    EVP_CIPHER_CTX_ctrl(aesctx,EVP_CTRL_AEAD_GET_TAG, 16, &CipherTxt[UserData.size()]);
    EVP_CIPHER_CTX_free(aesctx);
    EVP_PKEY_free(PubKey);
    BIO_free_all(PubKeyBio);
    EVP_PKEY_CTX_free(ctx);
    QByteArray ResultData;
    //ResultData.append(RandKey);
    ResultData.append((const char*)CipherKey,OutputSize);
    ResultData.append((const char*)RandIV,12);
    ResultData.append((const char*)CipherTxt,UserData.size()+16);
    ui->AREncOutput->setPlainText(QString::fromUtf8(ResultData.toBase64()));
    ui->AREncInput->setPlainText("");
    delete[] RandKey;
    delete[] CipherTxt;
    delete[] CipherKey;
    delete[] RandIV;
}


void MainWindow::on_ARDecryptBtn_clicked()
{
    QString MsgTampDisPrefix = "Message is original: ";
    QMessageBox msgbox;
    QByteArray MainData = QByteArray::fromBase64(ui->ARDecInput->toPlainText().toUtf8());
    BIO* PriKeyBio = BIO_new(BIO_s_mem());
    BIO_write(PriKeyBio,ui->PrivateKeyInput->toPlainText().toStdString().c_str(),ui->PrivateKeyInput->toPlainText().toUtf8().size());
    RSA* PriKeyRSA = PEM_read_bio_RSAPrivateKey(PriKeyBio,NULL,NULL,const_cast<char*>(""));
    if(PriKeyRSA == NULL) {
        msgbox.setIcon(QMessageBox::Icon::Critical);
        msgbox.setText("Invalid RSA Private key was provided");
        msgbox.exec();
        BIO_free_all(PriKeyBio);
        return;
    }
    if(MainData.size() < RSA_size(PriKeyRSA)+28) {
        msgbox.setIcon(QMessageBox::Icon::Critical);
        msgbox.setText("Invalid input has been supplied");
        msgbox.exec();
        BIO_free_all(PriKeyBio);
        return;
    }
    EVP_PKEY * PriKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(PriKey, PriKeyRSA);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(PriKey,NULL);
        if(EVP_PKEY_decrypt_init(ctx) <=0) {
            msgbox.setIcon(QMessageBox::Icon::Critical);
            msgbox.setText("Init failed");
            msgbox.exec();
            EVP_PKEY_free(PriKey);
            EVP_PKEY_CTX_free(ctx);
            BIO_free_all(PriKeyBio);
            return;
        }
        if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <=0) {
            msgbox.setIcon(QMessageBox::Icon::Critical);
            msgbox.setText("Padding Mode Failed");
            msgbox.exec();
            EVP_PKEY_free(PriKey);
            EVP_PKEY_CTX_free(ctx);
            BIO_free_all(PriKeyBio);
            return;
        }
        size_t OutSize = RSA_size(PriKeyRSA);
        unsigned char* AESKey = new unsigned char[OutSize];
        QByteArray EncryptedAESKey = MainData.sliced(0,OutSize);
        if(EVP_PKEY_decrypt(ctx,AESKey,&OutSize, (const unsigned char*)EncryptedAESKey.constData(),EncryptedAESKey.size()) <=0) {
            msgbox.setIcon(QMessageBox::Icon::Critical);
            msgbox.setText("Decryption Mode Failed");
            msgbox.exec();
            EVP_PKEY_free(PriKey);
            EVP_PKEY_CTX_free(ctx);
            BIO_free_all(PriKeyBio);
            delete[] AESKey;
            return;
        }
        QByteArray IV = MainData.sliced(RSA_size(PriKeyRSA),12);
        QByteArray Data = MainData.sliced(RSA_size(PriKeyRSA)+12,MainData.size()-RSA_size(PriKeyRSA)-12-16);
        QByteArray Tag = MainData.sliced(RSA_size(PriKeyRSA)+12+Data.length(),16);
        EVP_CIPHER_CTX *aesctx = EVP_CIPHER_CTX_new();
        const EVP_CIPHER * CipherMode;
        if((RSA_size(PriKeyRSA)/8)-42 < 32) {
            CipherMode = EVP_aes_128_gcm();
        } else {
            CipherMode = EVP_aes_256_gcm();
        }
        EVP_DecryptInit_ex(aesctx, CipherMode, NULL, AESKey, reinterpret_cast<const unsigned char*>(IV.data()));
        unsigned char* PlainTxt = new unsigned char[Data.length()];
        int OutputLen;
        EVP_DecryptUpdate(aesctx, PlainTxt, &OutputLen, reinterpret_cast<const unsigned char*>(Data.data()), Data.length());
        EVP_CIPHER_CTX_ctrl(aesctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)Tag.data());
        switch(EVP_DecryptFinal_ex(aesctx, PlainTxt, &OutputLen)) {
            case 1:
                // Decryption Correct
                ui->ARMessageStatus->setText(MsgTampDisPrefix+"Yes");
                break;
            case 0:
                // Decryption Bad
                ui->ARMessageStatus->setText(MsgTampDisPrefix+"No");
                break;
            default:
                // Bad Result
                ui->ARMessageStatus->setText(MsgTampDisPrefix+"Unknown");
                break;
        }
        ui->ARDecOutput->setPlainText(QString::fromUtf8(reinterpret_cast<char*>(PlainTxt),Data.length()));
        ui->ARDecInput->setPlainText("");
        EVP_PKEY_free(PriKey);
        EVP_PKEY_CTX_free(ctx);
        EVP_CIPHER_CTX_free(aesctx);
        BIO_free_all(PriKeyBio);
        delete[] AESKey;
        delete[] PlainTxt;
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

