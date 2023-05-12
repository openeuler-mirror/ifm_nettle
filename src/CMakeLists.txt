# lcr: utils library for iSula
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

set(check_incs
    ${LIBNETTLE_INCLUDE_DIR}
    )

set(check_nettle_libs
    ${LIBNETTLE_LIBRARY}
    ${LIBWD_LIBRARY}
    )

set(check_libgcrypt_libs
    ${LIBGCRYPT_LIBRARY}
    )

list(REMOVE_DUPLICATES check_incs)
list(REMOVE_DUPLICATES check_nettle_libs)

# get top source files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} topsrcs)
list(REMOVE_ITEM topsrcs "${CMAKE_CURRENT_SOURCE_DIR}/utils.c")
message("--  Get top srcs: " ${topsrcs})

if (ENABLE_LIBIFM_NETTLE)
    # set libifm_nettle library
    add_library(libifm_nettle SHARED ${topsrcs})

    set(libifm_nettle_incs
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_BINARY_DIR}/conf
        ${check_incs}
    )

    # set libifm_nettle include dirs
    target_include_directories(libifm_nettle
        PUBLIC ${libifm_nettle_incs}
        )

    # set libifm_nettle compile flags
    set_target_properties(libifm_nettle PROPERTIES PREFIX "")
    target_link_libraries(libifm_nettle ${check_nettle_libs} nettle)

    if (CMAKE_TOOLCHAIN_FILE)
        target_link_directories(libifm_nettle PUBLIC ${CMAKE_LIBRARY_PATH})
        target_link_libraries(libifm_nettle ${EXTRAL_LINK_LIBS})
    endif()


    add_library(libifm_nettle_s STATIC ${topsrcs})
    target_include_directories(libifm_nettle_s
        PUBLIC ${libifm_nettle_incs}
        )
    set_target_properties(libifm_nettle_s PROPERTIES PREFIX "")
    set_target_properties(libifm_nettle_s PROPERTIES OUTPUT_NAME libifm_nettle)

    # install all files
    install(TARGETS libifm_nettle
        LIBRARY DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
    install(TARGETS libifm_nettle_s
        ARCHIVE DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endif()


aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/gcrypt gcrypt_srcs)
list(REMOVE_ITEM gcrypt_srcs "${CMAKE_CURRENT_SOURCE_DIR}/gcrypt/utils.c")
message("--  Get top srcs: " ${gcrypt_srcs})

if (ENABLE_LIBIFM_LIBGCRYPT)
    # set libifm_libgcrypt library
    add_library(libifm_libgcrypt SHARED ${gcrypt_srcs})

    set(libifm_libgcrypt_incs
        ${CMAKE_CURRENT_SOURCE_DIR}/gcrypt
        ${CMAKE_BINARY_DIR}/conf
        ${check_incs}
    )

    # set libifm_libgcrypt include dirs
    target_include_directories(libifm_libgcrypt
        PUBLIC ${libifm_libgcrypt_incs}
        )

    # set libifm_libgcrypt compile flags
    set_target_properties(libifm_libgcrypt PROPERTIES PREFIX "")
    target_link_libraries(libifm_libgcrypt ${check_libgcrypt_libs} gcrypt)

    if (CMAKE_TOOLCHAIN_FILE)
        target_link_directories(libifm_libgcrypt PUBLIC ${CMAKE_LIBRARY_PATH})
        target_link_libraries(libifm_libgcrypt ${EXTRAL_LINK_LIBS})
    endif()


    add_library(libifm_libgcrypt_s STATIC ${gcrypt_srcs})
    target_include_directories(libifm_libgcrypt_s
        PUBLIC ${libifm_libgcrypt_incs}
        )
    set_target_properties(libifm_libgcrypt_s PROPERTIES PREFIX "")
    set_target_properties(libifm_libgcrypt_s PROPERTIES OUTPUT_NAME libifm_libgcrypt)

    # install all files
    install(TARGETS libifm_libgcrypt
        LIBRARY DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
    install(TARGETS libifm_libgcrypt_s
        ARCHIVE DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endif()
