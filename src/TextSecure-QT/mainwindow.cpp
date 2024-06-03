#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include "EncryptionHandler.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>

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
    QByteArray EncKey = ui->KeyInput->text().toUtf8();

    // Check if the key is supposed to be hashed
    if(!ui->isRawKey->isChecked())
        Utils::SHA256(&EncKey);

    // Start Encrypting
    switch(Encryption::IAES::Encrypt(EncKey,ui->EncInput->toPlainText().toUtf8(),Result)) {
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
    QByteArray EncKey = ui->KeyInput->text().toUtf8();

    // Check if the key is supposed to be hashed
    if(!ui->isRawKey->isChecked())
        Utils::SHA256(&EncKey);

    switch(Encryption::IAES::Decrypt(EncKey,QByteArray::fromBase64(ui->DecInput->toPlainText().toUtf8()),Result)) {
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
        msgbox->setText("RSA key size is too big. Maximum size is 16384. (Why do you need such as big size key? 2048 is already enough and some software doesn't support big sizes)");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        delete msgbox;
        return;
    }

    // Generate the keys
    EVP_PKEY *RSAKey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // ctx is nullable, handle it later
    EVP_PKEY_keygen_init(ctx); // <= 0 are ERRORS
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, UserKeySize);  // <= 0 are ERRORS
    if (EVP_PKEY_keygen(ctx, &RSAKey) <= 0) {
        msgbox->setText("RSA Key has failed to generate, please try again");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        delete msgbox;
        return;
    }

    // Set Private Key
    BIO* PriKeyBio = BIO_new(BIO_s_mem());
    if(PEM_write_bio_PKCS8PrivateKey(PriKeyBio, RSAKey,NULL,NULL,0,NULL,NULL) == 0) {
        msgbox->setText("Failed To Export Private Key");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        EVP_PKEY_free(RSAKey);
        delete msgbox;
        BIO_free_all(PriKeyBio);
        //RSA_free(RSAData);
        return;
    }
    BUF_MEM *PriKey;
    BIO_get_mem_ptr(PriKeyBio, &PriKey);
    ui->PrivateKeyInput->setPlainText(QString::fromUtf8(PriKey->data,PriKey->length));
    BIO_free_all(PriKeyBio);

    // Set Public Key
    BIO* PubKeyBio = BIO_new(BIO_s_mem());
    if(PEM_write_bio_PUBKEY(PubKeyBio,RSAKey) == 0) {
        msgbox->setText("Failed To Export Public Key");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        EVP_PKEY_free(RSAKey);
        delete msgbox;
        BIO_free_all(PubKeyBio);
        return;
    }
    BUF_MEM *PubKey;
    BIO_get_mem_ptr(PubKeyBio, &PubKey);
    ui->PublicKeyInput->setPlainText(QString::fromUtf8(PubKey->data,PubKey->length));
    BIO_free_all(PubKeyBio);

    msgbox->setText("RSA Key has been successfully generated");
    msgbox->setIcon(QMessageBox::Icon::Information);
    msgbox->exec();
    EVP_PKEY_free(RSAKey);
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

    // Read Private Key
    BIO* PriKeyBio = BIO_new(BIO_s_mem());
    BIO_write(PriKeyBio,ui->PrivateKeyInput->toPlainText().toStdString().c_str(),ui->PrivateKeyInput->toPlainText().toUtf8().size());
    EVP_PKEY* PriKey = PEM_read_bio_PrivateKey(PriKeyBio,NULL,NULL,const_cast<char*>(""));
    BIO_free_all(PriKeyBio);

    // Extract Public Key
    BIO* PubKeyBio = BIO_new(BIO_s_mem());
    if(PEM_write_bio_PUBKEY(PubKeyBio,PriKey) <= 0) {
        msgbox->setText("Failed To Convert Private Key To Public Key");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        delete msgbox;
        BIO_free_all(PubKeyBio);
        //RSA_free(RSAData);
        return;
    }
    BUF_MEM *PubKey;
    BIO_get_mem_ptr(PubKeyBio, &PubKey);
    ui->PublicKeyInput->setPlainText(QString::fromUtf8(PubKey->data,PubKey->length));
    BIO_free_all(PubKeyBio);

    msgbox->setIcon(QMessageBox::Icon::Information);
    msgbox->setText("Successfully extract public key from private key");
    msgbox->exec();
    delete msgbox;
}


void MainWindow::on_ImportPubCert_clicked()
{
    QMessageBox *msgbox = new QMessageBox(this);
    msgbox->setWindowTitle("Key Converter");

    // Get RSA Key From Cert
    BIO* CertKeyBio = BIO_new(BIO_s_mem());
    BIO_write(CertKeyBio,ui->PublicCertInput->toPlainText().toStdString().c_str(),ui->PublicCertInput->toPlainText().toUtf8().size());
    X509 * PubCert = PEM_read_bio_X509(CertKeyBio,NULL,NULL,NULL);
    EVP_PKEY * PubKey = X509_get_pubkey(PubCert);
    X509_free(PubCert);
    if(PubKey == NULL) {
        BIO_free_all(CertKeyBio);
        msgbox->setText("Invalid Certificate was provided");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        delete msgbox;
        return;
    }
    BIO_free_all(CertKeyBio);

    // Check if the key is RSA (ECC Pending...)
    if(EVP_PKEY_base_id(PubKey) != EVP_PKEY_RSA) {
        msgbox->setText("Certificate is not a RSA-based");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        EVP_PKEY_free(PubKey);
        delete msgbox;
        return;
    }

    BUF_MEM *PubKeyBuff;
    BIO* PubKeyBio = BIO_new(BIO_s_mem());
    if(PEM_write_bio_PUBKEY(PubKeyBio,PubKey)  <= 0) {
        msgbox->setText("Unable to convert certificate to public key");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        EVP_PKEY_free(PubKey);
        BIO_free_all(PubKeyBio);
        delete msgbox;
        return;
    }
    EVP_PKEY_free(PubKey);

    BIO_get_mem_ptr(PubKeyBio, &PubKeyBuff);
    ui->PublicKeyInput->setPlainText(QString::fromUtf8(PubKeyBuff->data,PubKeyBuff->length));
    ui->PublicCertInput->setPlainText("");
    BIO_free_all(PubKeyBio);

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

    EVP_PKEY * RSAKey = PEM_read_bio_PrivateKey(PriKeyBio,NULL,NULL,const_cast<char*>(""));
    if(RSAKey == NULL) {
        msgbox->setText("Invalid RSA Private key was provided or you're trying to encrypt an already encrypted key");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        BIO_free_all(PriKeyBio);
        delete msgbox;
        return;
    }
    BIO_free_all(PriKeyBio);

    BIO* EncPriKeyBio = BIO_new(BIO_s_mem());
    if(PEM_write_bio_PKCS8PrivateKey(EncPriKeyBio,RSAKey,EVP_des_ede3_cbc(),NULL,0,0,ui->PriKeyPassInput->text().toUtf8().data()) <= 0) {
        msgbox->setText("Failed To Encrypt Private Key or you forgot to set a passphrase");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        delete msgbox;
        BIO_free_all(EncPriKeyBio);
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
    BIO_free_all(EncPriKeyBio);
}


void MainWindow::on_PriKeyDecBtn_clicked()
{
    QMessageBox *msgbox = new QMessageBox(this);
    msgbox->setWindowTitle("Key Encryptor");

    BIO* PriKeyBio = BIO_new(BIO_s_mem());
    BIO_write(PriKeyBio,ui->PrivateKeyInput->toPlainText().toStdString().c_str(),ui->PrivateKeyInput->toPlainText().toUtf8().size());
    EVP_PKEY * RSAKey = PEM_read_bio_PrivateKey(PriKeyBio,NULL,0,ui->PriKeyPassInput->text().toUtf8().data());
    if(RSAKey == NULL) {
        msgbox->setText("Invalid Private Key or Passphrase");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        EVP_PKEY_free(RSAKey);
        delete msgbox;
        return;
    }
    BIO_free_all(PriKeyBio);

    BIO* EncPriKeyBio = BIO_new(BIO_s_mem());
    if(PEM_write_bio_PKCS8PrivateKey(EncPriKeyBio,RSAKey,NULL,NULL,0,NULL,NULL) <= 0) {
        msgbox->setText("Failed To Decrypt Private Key");
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->exec();
        delete msgbox;
        BIO_free_all(EncPriKeyBio);
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
    BIO_free_all(EncPriKeyBio);
}

void MainWindow::on_AREncryptBtn_clicked()
{
    QMessageBox * msgbox = new QMessageBox(this);
    msgbox->setWindowTitle("AES/RSA Encryption");

    // Prepare Random AES Key
    unsigned char RandKey[32];
    int KeySize = 0;
    if((Encryption::IRSA::KeySize(ui->PublicKeyInput->toPlainText().toUtf8(),true)/8)-42 < 32)
        KeySize = 16;
    else
        KeySize = 32;
    RandByte(RandKey, KeySize);

    QByteArray * EncryptedAESKey = new QByteArray();
    switch(Encryption::IRSA::Encrypt(ui->PublicKeyInput->toPlainText().toUtf8(),QByteArray::fromRawData((const char*)RandKey,KeySize),EncryptedAESKey)) {
    case 1:
        break;
    case 0:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Invalid Public RSA Key has been detected");
        msgbox->exec();
        delete EncryptedAESKey;
        delete msgbox;
        return;
    case -4:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Unable to encrypt your AES Key");
        msgbox->exec();
        delete EncryptedAESKey;
        delete msgbox;
        return;
    default:
        msgbox->setIcon(QMessageBox::Icon::Critical);
        msgbox->setText("Something else went wrong");
        msgbox->exec();
        delete EncryptedAESKey;
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
        delete msgbox;
        return;
    }

    // Cleanup
    memset(RandKey, 0, KeySize); // Erase the key from existance
    delete EncryptedAESKey;
    delete EncData;
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
        ui->ARMessageStatus->setText("Message is original: No");
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


void MainWindow::on_isRawKey_stateChanged(int state)
{
    QString original = "Your AES Key Here";
    QString message = " (16, 24, or 32 bytes long (or characters if each character is worth 1 byte))";

    // Unchecked or use SHA1 hashed key message
    if(state == 0)
        ui->KeyInput->setPlaceholderText(original);
    else if (state == 2) // Checked or raw key encryption message
        ui->KeyInput->setPlaceholderText(original + message);
    ui->genAESKeyBtn->setEnabled(state == 2);
}


void MainWindow::on_genAESKeyBtn_clicked()
{
    // Possible password combination
    const char strList[78] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
                       '1','2','3','4','5','6','7','8','9','0','!','#','*','&','+','-',':','?','@','$','%','=','^',';',':','~',
                      'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'};

    // Generate random bytes and convert it to password string
    unsigned int rngPwd[32];
    RandByte(rngPwd, 32*sizeof(int));
    QString TextPassword = "";
    for(char i=0; i<32; i++)
        TextPassword += strList[rngPwd[i] % 78];

    // Set the password on the textbox
    ui->KeyInput->setText(TextPassword);
}

