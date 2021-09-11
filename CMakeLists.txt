# Configure CMake Requirement
cmake_minimum_required(VERSION 3.13)
set(MAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Setup the projects
project(TextSecure VERSION 1.0)

# Setup the configurations
#SET(SENTRY_BACKEND crashpad CACHE STRING "Sentry Backend" FORCE)
#SET(BUILD_EXAMPLES OFF CACHE BOOL "Build discord-rpc example" FORCE)

# Setup the output dir
#set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/alib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Start the build stuff
add_subdirectory(src)