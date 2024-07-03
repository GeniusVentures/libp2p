
set(BUILD_EXAMPLES ON)
set(EXPOSE_MOCKS ON)
set(CMAKE_USE_OPENSSL ON)
set(TESTING OFF)

#GTest
set(GTest_DIR "${CMAKE_SOURCE_DIR}/../build/Windows/Debug/GTest/lib/cmake/GTest")
#Boost 
set(BOOST_VERSION "1.85.0")
set(Boost_NO_SYSTEM_PATHS OFF)
set(BOOST_LIB_CMAKE_DIR "${CMAKE_SOURCE_DIR}/../build/Windows/Debug/boost/build/Windows/lib/cmake")
set(boost_headers_DIR ${BOOST_LIB_CMAKE_DIR}/boost_headers-${BOOST_VERSION})
set(boost_random_DIR ${BOOST_LIB_CMAKE_DIR}/boost_random-${BOOST_VERSION})
set(boost_system_DIR ${BOOST_LIB_CMAKE_DIR}/boost_system-${BOOST_VERSION})
set(boost_filesystem_DIR ${BOOST_LIB_CMAKE_DIR}/boost_filesystem-${BOOST_VERSION})
set(boost_program_options_DIR ${BOOST_LIB_CMAKE_DIR}/boost_program_options-${BOOST_VERSION})
set(boost_regex_DIR ${BOOST_LIB_CMAKE_DIR}/boost_regex-${BOOST_VERSION})
set(boost_date_time_DIR ${BOOST_LIB_CMAKE_DIR}/boost_date_time-${BOOST_VERSION})
set(Boost_DIR ${BOOST_LIB_CMAKE_DIR}/Boost-${BOOST_VERSION})
set(BOOST_ROOT ${CMAKE_SOURCE_DIR}/../build/Windows/Debug/boost/build/Windows/)
set(Boost_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/../build/Windows/Debug/boost/build/Windows/include/boost-1_85)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME ON)
set(Boost_USE_STATIC_LIBS ON)
set(Boost_NO_SYSTEM_PATHS ON)
include_directories(${Boost_INCLUDE_DIR})

#OpenSSL
set(OPENSSL_USE_STATIC_LIBS ON)
set(OPENSSL_MSVC_STATIC_RT ON)
set(OPENSSL_ROOT_DIR ${CMAKE_SOURCE_DIR}/../build/Windows/Debug/openssl/build/Windows/)
set(OPENSSL_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/../build/Windows/Debug/openssl/build/Windows/include)
set(OPENSSL_LIBRARIES ${CMAKE_SOURCE_DIR}/../build/Windows/Debug/openssl/build/Windows/lib)
include_directories(${OPENSSL_INCLUDE_DIR})

#Protobuf
set(Protobuf_DIR ${CMAKE_SOURCE_DIR}/../build/Windows/Debug/protobuf/cmake)
set(Protobuf_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/../build/Windows/Debug/protobuf/include)
set(Protobuf_LIBRARIES ${CMAKE_SOURCE_DIR}/../build/Windows/Debug/protobuf/lib)
set(Protobuf_PROTOC_EXECUTABLE ${CMAKE_SOURCE_DIR}/../build/Windows/Debug/protobuf/bin/protoc)


set(c-ares_DIR ${CMAKE_SOURCE_DIR}/../build/Windows/Debug/cares/lib/cmake/c-ares)
set(fmt_DIR ${CMAKE_SOURCE_DIR}/../build/Windows/Debug/fmt/lib/cmake/fmt)
set(yaml-cpp_DIR ${CMAKE_SOURCE_DIR}/../build/Windows/Debug/yaml-cpp/lib/cmake/yaml-cpp)
set(soralog_DIR ${CMAKE_SOURCE_DIR}/../build/Windows/Debug/soralog/lib/cmake/soralog)
set(tsl_hat_trie_DIR ${CMAKE_SOURCE_DIR}/../build/Windows/Debug/tsl_hat_trie/lib/cmake/tsl_hat_trie)

set(Boost.DI_DIR ${CMAKE_SOURCE_DIR}/../build/Windows/Debug/Boost.DI/lib/cmake/Boost.DI)

set(SQLiteModernCpp_DIR ${CMAKE_SOURCE_DIR}/../build/Windows/Debug/SQLiteModernCpp/lib/cmake/SQLiteModernCpp)
set(sqlite3_DIR ${CMAKE_SOURCE_DIR}/../build/Windows/Debug/sqlite3/lib/cmake/sqlite3)


include_directories(${CMAKE_SOURCE_DIR}/../build/Windows/Debug/Microsoft.GSL/include)