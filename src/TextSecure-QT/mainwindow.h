#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

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

    void on_GenRSAKey_clicked();

    void on_REncryptBtn_clicked();

    void on_RDecryptBtn_clicked();

    void on_REncryptClear_clicked();

    void on_RDecryptClear_clicked();

    void on_PriToPubKeyBtn_clicked();

    void on_ImportPubCert_clicked();

    void on_PriKeyEncBtn_clicked();

    void on_PriKeyDecBtn_clicked();

    void on_AREncryptBtn_clicked();

    void on_AREncryptClear_clicked();

    void on_ARDecryptBtn_clicked();

    void on_ARDecryptClear_clicked();


    void on_isRawKey_stateChanged(int arg1);

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
