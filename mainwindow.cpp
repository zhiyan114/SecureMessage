#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <ctime>
#include <stdio.h>
#include <process.h>


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
    srand( (unsigned) time(NULL) * _getpid());
    for (int i=0;i<size;i++) {
        RandFilling[i] = rand()%255;
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
        break;
       default:
        // Dont do it
        break;
    }
}

