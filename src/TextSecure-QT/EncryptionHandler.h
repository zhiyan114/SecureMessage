#ifndef ENCRYPTIONHANDLER_H
#define ENCRYPTIONHANDLER_H
#include <QByteArray>
namespace Encryption {
namespace IAES {
int Encrypt(QByteArray Key, QByteArray Data, QByteArray * Result);
int Decrypt(QByteArray Key, QByteArray Data, QByteArray * Result);
}
namespace IRSA {
int Encrypt(QByteArray PubKey, QByteArray Data, QByteArray * Result);
int Decrypt(QByteArray PriKey, QByteArray Data, QByteArray * Result);
int KeySize(QByteArray RSAKey, bool isPublic);
}
}

namespace Utils {
int SHA256(QByteArray * data);
}

void RandByte(unsigned char* byteArr,int size);
#endif // ENCRYPTIONHANDLER_H
