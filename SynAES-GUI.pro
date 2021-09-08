QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    main.cpp \
    mainwindow.cpp

HEADERS += \
    mainwindow.h

FORMS += \
    mainwindow.ui

# Default rules for deployment.

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/'../../../../Program Files/OpenSSL-Win64/lib/' -llibcrypto
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/'../../../../Program Files/OpenSSL-Win64/lib/' -llibcrypto
else:unix: LIBS += -L$$PWD/'../../../../Program Files/OpenSSL-Win64/lib/' -llibcrypto

INCLUDEPATH += $$PWD/'../../../../Program Files/OpenSSL-Win64/include'
DEPENDPATH += $$PWD/'../../../../Program Files/OpenSSL-Win64/include'
