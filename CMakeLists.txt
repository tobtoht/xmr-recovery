cmake_minimum_required(VERSION 2.8.7)
project(xmr-recovery)

list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_SOURCE_DIR}/cmake")
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(FetchContent)
include(FindCcache)
include(CheckIncludeFile)
include(CheckSymbolExists)

set(BUILD_GUI_DEPS OFF)
option(ARCH "Target architecture" "x86-64")
set(BUILD_64 ON)
set(USE_SINGLE_BUILDDIR ON)

add_subdirectory(monero)

set(recovery_sources
        recovery.cpp)

monero_add_executable(recovery
        ${recovery_sources})

target_include_directories(recovery PUBLIC
        ${CMAKE_SOURCE_DIR}/monero/include
        ${CMAKE_SOURCE_DIR}/monero/src
        ${CMAKE_SOURCE_DIR}/monero/contrib/epee/include
        ${CMAKE_SOURCE_DIR}/monero/external/easylogging++
        ${CMAKE_SOURCE_DIR}/monero/external/rapidjson/include)

target_link_libraries(recovery
        PRIVATE
        cryptonote_core
        cncrypto
        common
        mnemonics
        version
        ${Boost_CHRONO_LIBRARY}
        ${Boost_PROGRAM_OPTIONS_LIBRARY}
        ${Boost_FILESYSTEM_LIBRARY}
        ${Boost_LOCALE_LIBRARY}
        ${ICU_LIBRARIES}
        ${Boost_THREAD_LIBRARY}
        ${CMAKE_THREAD_LIBS_INIT}
        ${GNU_READLINE_LIBRARY}
        ${EXTRA_LIBRARIES})

set_property(TARGET recovery
        PROPERTY
        OUTPUT_NAME "recovery")
