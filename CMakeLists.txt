cmake_minimum_required(VERSION 3.10)
project(ECDH_AES256)

# Include directories
set(INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(SOURCE_DIR  "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(OPENSSL_USE_STATIC_LIBS TRUE)
set(CMAKE_THREAD_LIBS_INIT "-lpthread")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(CMAKE_HAVE_THREADS_LIBRARY 1)
set(CMAKE_USE_WIN32_THREADS_INIT 0)
set(CMAKE_USE_PTHREADS_INIT 1)
set(THREADS_PREFER_PTHREAD_FLAG ON)


# Find all source files in the src directory
file(GLOB_RECURSE PROJECT_FILES
        "${INCLUDE_DIR}/*.h"
        "${SOURCE_DIR}/*.cpp"
        "${SOURCE_DIR}/*.c"
)

add_executable("${PROJECT_NAME}" ${PROJECT_FILES})

target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE ssl crypto)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)

