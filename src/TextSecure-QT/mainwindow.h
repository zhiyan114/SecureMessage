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

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
