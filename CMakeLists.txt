# ifm_nettle: utils library for iSula
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

cmake_minimum_required (VERSION 2.8)
project (ifm_nettle)

option(VERSION "set ifm_nettle version" ON)
if (VERSION STREQUAL "ON")
	set(IFM_NETTLE_VERSION "0.1.0")
endif()

option(DEBUG "set ifm_nettle gcc option" ON)
if (DEBUG STREQUAL "ON")
    add_definitions("-g -O2")
endif()

option(ENABLE_UT "enable ut" ON)

include(cmake/options.cmake)

include(cmake/set_build_flags.cmake)

if (LIB_INSTALL_DIR)
  set(LIB_INSTALL_DIR_DEFAULT ${LIB_INSTALL_DIR})
else()
  set(LIB_INSTALL_DIR_DEFAULT "lib")
endif()

if (INCLUDE_INSTALL_DIR)
  set(INCLUDE_INSTALL_DIR_DEFAULT ${INCLUDE_INSTALL_DIR})
else()
  set(INCLUDE_INSTALL_DIR_DEFAULT "include")
endif()

# check depends libs and headers
include(cmake/checker.cmake)
if (CHECKER_RESULT)
	return()
endif()

# Get the latest abbreviated commit hash of the working branch
execute_process(
  COMMAND git rev-parse HEAD
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
message("--  commit id: " ${GIT_COMMIT_HASH})

add_definitions(-DIFM_NETTLEPATH="${CMAKE_INSTALL_PREFIX}/var/lib/ifm_nettle")
add_definitions(-DLOGPATH="${CMAKE_INSTALL_PREFIX}/var/log/ifm_nettle")
add_definitions(-DIFM_NETTLE_GIT_COMMIT="${GIT_COMMIT_HASH}")
add_definitions(-DHAVE_ISULAD)

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
	"${CMAKE_BINARY_DIR}/conf/config.h"
)

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/ifm_nettle.pc.in"
	"${CMAKE_BINARY_DIR}/conf/ifm_nettle.pc"
)

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/ifm_libgcrypt.pc.in"
	"${CMAKE_BINARY_DIR}/conf/ifm_libgcrypt.pc"
)

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/ifm_libxcrypt.pc.in"
	"${CMAKE_BINARY_DIR}/conf/ifm_libxcrypt.pc"
)

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/ifm_libverto.pc.in"
	"${CMAKE_BINARY_DIR}/conf/ifm_libverto.pc"
)

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/ifm_libhv2ev.pc.in"
	"${CMAKE_BINARY_DIR}/conf/ifm_libhv2ev.pc"
)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/src)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/bench)
# unit test and coverage
set(CMAKE_VERBOSE_MAKEFILE OFF)
if(ENABLE_GCOV)
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        message(WARNING "Debugging mode should be turned on when generating code coverage reports, otherwise coverage may be inaccurate")
    endif()
    MESSAGE(STATUS "Enable coverage compile option")
    set(COVERAGE_C_OPTION "${COVERAGE_OPTION} -fprofile-arcs -ftest-coverage -fkeep-static-functions -fkeep-inline-functions")
    set(COVERAGE_CXX_OPTION "${COVERAGE_OPTION} -fprofile-arcs -ftest-coverage")
endif(ENABLE_GCOV)

if(ENABLE_ASAN)
    MESSAGE(STATUS "Enable asan compile option")
    SET(ASAN_OPTIONS "${ASAN_OPTION} -fsanitize=address -fsanitize-recover=address -fno-omit-frame-pointer")
endif(ENABLE_ASAN)

if(CMAKE_BUILD_TYPE STREQUAL Debug)
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${COVERAGE_C_OPTION} ${ASAN_OPTIONS}")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${COVERAGE_CXX_OPTION} ${ASAN_OPTIONS}")
endif()

if(ENABLE_UT)
    include(CTest)
    include(Dart)
    find_program(MEMORYCHECK_COMMAND NAMES valgrind)
    set(MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full")
    enable_testing()
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tests)
endif()

# install all files
install(FILES ${CMAKE_BINARY_DIR}/conf/ifm_nettle.pc
	DESTINATION ${LIB_INSTALL_DIR_DEFAULT}/pkgconfig PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE WORLD_READ WORLD_EXECUTE)

# install all files
install(FILES ${CMAKE_BINARY_DIR}/conf/ifm_libgcrypt.pc
	DESTINATION ${LIB_INSTALL_DIR_DEFAULT}/pkgconfig PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE WORLD_READ WORLD_EXECUTE)

# install all files
install(FILES ${CMAKE_BINARY_DIR}/conf/ifm_libxcrypt.pc
	DESTINATION ${LIB_INSTALL_DIR_DEFAULT}/pkgconfig PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE WORLD_READ WORLD_EXECUTE)

# install all files
install(FILES ${CMAKE_BINARY_DIR}/conf/ifm_libverto.pc
	DESTINATION ${LIB_INSTALL_DIR_DEFAULT}/pkgconfig PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE WORLD_READ WORLD_EXECUTE)

# install all files
install(FILES ${CMAKE_BINARY_DIR}/conf/ifm_libhv2ev.pc
	DESTINATION ${LIB_INSTALL_DIR_DEFAULT}/pkgconfig PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE WORLD_READ WORLD_EXECUTE)

# uninstall
if(NOT TARGET uninstall)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
  IMMEDIATE @ONLY)

add_custom_target(uninstall
  COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()
