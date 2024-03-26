#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>
#include "C:/Qt/Tools/OpenSSLv3/Win_x64/include/openssl/evp.h"
#include "C:/Qt/Tools/OpenSSLv3/Win_x64/include/openssl/macros.h"


QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class Credentinals {
public:
    QString site;
    QString login;
    QString password;
};

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    bool readJSON(QByteArray key_hex);
    bool loginClicked;
    bool passwordClicked;

    QByteArray showPinDialog();

public slots:
    void Search(const QString &fragment);
    int decryptFile(const QByteArray &encryptedBytes, const QByteArray &key_hex, QByteArray &decryptedBytes);

private slots:
    void decryptLogin(int id);
    void decryptPassword(int id);
    void on_edtPin_returnPressed();

private:
    Ui::MainWindow *ui;
    QJsonArray m_jsonarray;
    EVP_CIPHER_CTX *ctx;
    bool m_isStartup = true;
    int m_current_id=-1;
    QByteArray decrypted_creds;
    QByteArray m_keyHash;
    QString m_storedHash;
};
#endif // MAINWINDOW_H
