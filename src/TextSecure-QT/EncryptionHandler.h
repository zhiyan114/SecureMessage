#ifndef ENCRYPTIONHANDLER_H
#define ENCRYPTIONHANDLER_H
#include <QByteArray>
namespace Encryption {
namespace AES {
int Encrypt(QByteArray Key, QByteArray Data);
int Decrypt(QByteArray Key, QByteArray Data);
}
namespace RSA {
int Encrypt(QByteArray PubKey, QByteArray Data);
int Decrypt(QByteArray PriKey, QByteArray Data);
}
}
#endif // ENCRYPTIONHANDLER_H
