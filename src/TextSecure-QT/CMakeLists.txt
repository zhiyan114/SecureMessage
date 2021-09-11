# Find important libs
find_package(Qt6 COMPONENTS Widgets REQUIRED)
find_package(OpenSSL REQUIRED)
# Handle QT Internals
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
# Add the executable
add_executable(SecureText-qt
    mainwindow.ui
    mainwindow.cpp
    mainwindow.h
    main.cpp
)
# Link the libs
target_link_libraries(SecureText-qt Qt6::Widgets OpenSSL::Crypto)
