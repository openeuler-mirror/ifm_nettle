# iSula-libutils: utils library for iSula
#
# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
#
# Authors:
# Haozi007 <liuhao27@huawei.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#

enable_testing()
find_package(GTest REQUIRED)

macro(_DEFINE_NEW_TEST)
    add_executable(${ARGV0}
        ${TESTS_UTILS_SRCS}
        main.cpp
        ${ARGV0}.cpp
        testutils.cpp
        )

    target_link_libraries(${ARGV0}
        ${GTEST_LIBRARY}
        pthread
        libifm_nettle
        libifm_libgcrypt
        libifm_libxcrypt
        gpg-error
        gmp
        )

    target_include_directories(${ARGV0} PUBLIC
        ${GTEST_INCLUDE_DIR}
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/gcrypt
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/xcrypt
        PUBLIC ${CMAKE_SOURCE_DIR}/src
        PUBLIC ${CMAKE_SOURCE_DIR}/src/gcrypt
        PUBLIC ${CMAKE_SOURCE_DIR}/src/xcrypt
        )
        
    add_test(
        NAME ${ARGV1}
        COMMAND ${ARGV0}
        --gtest_output=xml:${ARGV1}-Results.xml
    )
endmacro()

# --------------- testcase add here -----------------

# fuzz test
option(ENABLE_FUZZ "set ifm_nettle fuzz option" OFF)
if (ENABLE_FUZZ)
    add_subdirectory(fuzz)
endif()

#   api testcase
_DEFINE_NEW_TEST(sm3_ut sm3_testcase)
_DEFINE_NEW_TEST(md5_ut md5_testcase)
_DEFINE_NEW_TEST(sha224_ut sha224_testcase)
_DEFINE_NEW_TEST(sha256_ut sha256_testcase)
_DEFINE_NEW_TEST(sha384_ut sha384_testcase)
_DEFINE_NEW_TEST(sha512_ut sha512_testcase)
_DEFINE_NEW_TEST(sha512_224_ut sha512_224_testcase)
_DEFINE_NEW_TEST(sha512_256_ut sha512_256_testcase)
_DEFINE_NEW_TEST(gcrypt_md_ut gcrypt_md_testcases)
_DEFINE_NEW_TEST(gcrypt_pk_ut gcrypt_pk_testcases)
_DEFINE_NEW_TEST(aes_ut aes_testcases)
_DEFINE_NEW_TEST(gcm_ut gcm_testcases)
_DEFINE_NEW_TEST(rsa_ut rsa_testcases)
_DEFINE_NEW_TEST(gcrypt_basic_ut gcrypt_basic_testcases)
_DEFINE_NEW_TEST(xcrypt_basic_ut xcrypt_basic_testcases)
_DEFINE_NEW_TEST(hmac_ut hmac_testcases)
_DEFINE_NEW_TEST(gcrypt_basic_cipher_ut gcrypt_basic_cipher_testcases)



# mock test for run lcov to generate html
add_executable(mock_ut main.cpp)
target_include_directories(mock_ut PUBLIC
    ${GTEST_INCLUDE_DIR}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    )
target_link_libraries(mock_ut
    ${GTEST_LIBRARY}
    pthread
    )

add_dependencies(mock_ut sm3_ut md5_ut sha224_ut sha256_ut sha384_ut sha512_ut sha512_224_ut sha512_256_ut gcrypt_md_ut gcrypt_pk_ut aes_ut gcm_ut rsa_ut gcrypt_basic_ut xcrypt_basic_ut hmac_ut gcrypt_basic_cipher_ut)

# gcrypt benchmark
add_executable(gcrypt_benchmark gcrypt_benchmark.cpp)
target_include_directories(gcrypt_benchmark PUBLIC
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/gcrypt
    PUBLIC ${CMAKE_SOURCE_DIR}/src
    PUBLIC ${CMAKE_SOURCE_DIR}/src/gcrypt
    )
target_link_libraries(gcrypt_benchmark
    pthread
    libifm_libgcrypt
    gpg-error
    )

IF(ENABLE_GCOV)
    add_custom_target(coverage
        COMMAND lcov --directory . --zerocounters --rc lcov_branch_coverage=1
        COMMAND lcov -c -i -d . -o coverage.base --rc lcov_branch_coverage=1

        COMMAND ctest

        COMMAND lcov --directory . --capture --output-file coverage.info --rc lcov_branch_coverage=1
        COMMAND lcov -a coverage.base -a coverage.info --output-file coverage.total --rc lcov_branch_coverage=1
        COMMAND lcov --remove coverage.total '/usr/*' '*/json/*' --output-file ${PROJECT_BINARY_DIR}/coverage.info.cleaned --rc lcov_branch_coverage=1
        COMMAND genhtml -o coverage ${PROJECT_BINARY_DIR}/coverage.info.cleaned --branch-coverage --rc lcov_branch_coverage=1
        COMMAND ${CMAKE_COMMAND} -E remove coverage.base coverage.total ${PROJECT_BINARY_DIR}/coverage.info.cleaned

        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
        COMMENT "generating report..."
    )

    add_custom_command(TARGET coverage POST_BUILD
        COMMAND ;
        COMMENT "open .test/coverage/index.html in browser to view the coverage analysis report."
    )
ENDIF(ENABLE_GCOV)
# --------------- testcase add finish -----------------

