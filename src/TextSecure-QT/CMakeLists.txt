# Find important libs
find_package(Qt5 COMPONENTS Widgets REQUIRED)
find_package(OpenSSL REQUIRED)
# Handle QT Internals
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
# Add the executable
if(MSVC OR MSYS OR MINGW)
    add_executable(SecureText-qt WIN32
        mainwindow.ui
        mainwindow.cpp
        mainwindow.h
        main.cpp
        EncryptionHandler.h
        EncryptionHandler.cpp
    )
endif()
if(UNIX AND NOT APPLE)
    add_executable(SecureText-qt
        mainwindow.ui
        mainwindow.cpp
        mainwindow.h
        main.cpp
        EncryptionHandler.h
        EncryptionHandler.cpp
    )
endif()

# Link the libs
target_link_libraries(SecureText-qt Qt5::Widgets OpenSSL::Crypto)
