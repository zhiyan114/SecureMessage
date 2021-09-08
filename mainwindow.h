#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <openssl/bio.h>
#include <openssl/evp.h>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_EncryptBtn_clicked();

    void on_DecryptBtn_clicked();

    void on_EncClear_clicked();

    void on_DecClear_clicked();

private:
    Ui::MainWindow *ui;
    const EVP_CIPHER * CipherType;
};
#endif // MAINWINDOW_H
