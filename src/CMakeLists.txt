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
    ${LIBWD_LIBRARY}
    )

set(check_libxcrypt_libs
    ${LIBXCRYPT_LIBRARY}
    )

set(check_libverto_libs
    ${LIBVERTO_LIBRARY}
    ${LIBHV_LIBRARY}
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
    target_link_libraries(libifm_nettle ${check_nettle_libs} nettle hogweed)

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
    file(GLOB nettle_incs "${CMAKE_CURRENT_SOURCE_DIR}/*.h")
    install(FILES ${nettle_incs} DESTINATION ${INCLUDE_INSTALL_DIR_DEFAULT}/ifm/ PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)
endif()


aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/gcrypt gcrypt_srcs)
list(APPEND gcrypt_srcs "${CMAKE_CURRENT_SOURCE_DIR}/ifm_utils.c")
message("--  Get top srcs: " ${gcrypt_srcs})

if (ENABLE_LIBIFM_LIBGCRYPT)
    # set libifm_libgcrypt library
    add_library(libifm_libgcrypt SHARED ${gcrypt_srcs})

    set(libifm_libgcrypt_incs
        ${CMAKE_CURRENT_SOURCE_DIR}/
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
        install(FILES gcrypt/ifm_gcrypt.h DESTINATION ${INCLUDE_INSTALL_DIR_DEFAULT}/ifm/ PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)
endif()

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/xcrypt xcrypt_srcs)
list(REMOVE_ITEM xcrypt_srcs "${CMAKE_CURRENT_SOURCE_DIR}/xcrypt/utils.c")
message("--  Get top srcs: " ${xcrypt_srcs})

if (ENABLE_LIBIFM_LIBXCRYPT)
    # set libifm_libxcrypt library
    add_library(libifm_libxcrypt SHARED ${xcrypt_srcs})

    set(libifm_libxcrypt_incs
        ${CMAKE_CURRENT_SOURCE_DIR}/xcrypt
        ${CMAKE_BINARY_DIR}/conf
        ${check_incs}
    )

    # set libifm_libxcrypt include dirs
    target_include_directories(libifm_libxcrypt
        PUBLIC ${libifm_libxcrypt_incs}
        )

    # set libifm_libxcrypt compile flags
    set_target_properties(libifm_libxcrypt PROPERTIES PREFIX "")
    target_link_libraries(libifm_libxcrypt ${check_libxcrypt_libs} crypt)

    if (CMAKE_TOOLCHAIN_FILE)
        target_link_directories(libifm_libxcrypt PUBLIC ${CMAKE_LIBRARY_PATH})
        target_link_libraries(libifm_libxcrypt ${EXTRAL_LINK_LIBS})
    endif()


    add_library(libifm_libxcrypt_s STATIC ${xcrypt_srcs})
    target_include_directories(libifm_libxcrypt_s
        PUBLIC ${libifm_libxcrypt_incs}
        )
    set_target_properties(libifm_libxcrypt_s PROPERTIES PREFIX "")
    set_target_properties(libifm_libxcrypt_s PROPERTIES OUTPUT_NAME libifm_libxcrypt)

    # install all files
    install(TARGETS libifm_libxcrypt
        LIBRARY DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
    install(TARGETS libifm_libxcrypt_s
        ARCHIVE DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
    install(FILES xcrypt/ifm_crypt.h DESTINATION ${INCLUDE_INSTALL_DIR_DEFAULT}/ifm/ PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)
endif()

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/hv2ev hv2ev_srcs)
# list(REMOVE_ITEM hv2ev_srcs "${CMAKE_CURRENT_SOURCE_DIR}/hv2ev/utils.c")
message("--  Get top srcs: " ${hv2ev_srcs})

if (ENABLE_LIBIFM_LIBHV2EV)
    # set libifm_libhv2ev library
    add_library(libifm_libhv2ev SHARED ${hv2ev_srcs})

    set(libifm_libhv2ev_incs
        ${CMAKE_CURRENT_SOURCE_DIR}/hv2ev
        ${CMAKE_BINARY_DIR}/conf
        ${check_incs}
    )

    # set libifm_libhv2ev include dirs
    target_include_directories(libifm_libhv2ev
        PUBLIC ${libifm_libhv2ev_incs}
        )

    # set libifm_libhv2ev compile flags
    set_target_properties(libifm_libhv2ev PROPERTIES PREFIX "")
    target_link_libraries(libifm_libhv2ev ${check_libhv_libs} hv)

    if (CMAKE_TOOLCHAIN_FILE)
        target_link_directories(libifm_libhv2ev PUBLIC ${CMAKE_LIBRARY_PATH})
        target_link_libraries(libifm_libhv2ev ${EXTRAL_LINK_LIBS})
    endif()


    add_library(libifm_libhv2ev_s STATIC ${hv2ev_srcs})
    target_include_directories(libifm_libhv2ev_s
        PUBLIC ${libifm_libhv2ev_incs}
        )
    set_target_properties(libifm_libhv2ev_s PROPERTIES PREFIX "")
    set_target_properties(libifm_libhv2ev_s PROPERTIES OUTPUT_NAME libifm_libhv2ev)

    # install all files
    install(TARGETS libifm_libhv2ev
        LIBRARY DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
    install(TARGETS libifm_libhv2ev_s
        ARCHIVE DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
    install(FILES hv2ev/hv2ev.h DESTINATION ${INCLUDE_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)
endif()

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/verto verto_srcs)
message("--  Get top srcs: " ${verto_srcs})

if (ENABLE_LIBIFM_LIBVERTO)
    # set libifm_libverto library
    add_library(libifm_libverto SHARED ${verto_srcs})

    set(libifm_verto_incs
        ${CMAKE_CURRENT_SOURCE_DIR}/verto
    )

    # set libifm_libverto include dirs
    target_include_directories(libifm_libverto
        PUBLIC ${libifm_verto_incs}
        )

    # set libifm_libverto compile flags
    set_target_properties(libifm_libverto PROPERTIES PREFIX "")
    target_link_libraries(libifm_libverto ${check_libverto_libs} verto hv)

    if (CMAKE_TOOLCHAIN_FILE)
        target_link_directories(libifm_libverto PUBLIC ${CMAKE_LIBRARY_PATH})
        target_link_libraries(libifm_libverto ${EXTRAL_LINK_LIBS})
    endif()


    add_library(libifm_libverto_s STATIC ${verto_srcs})
    target_include_directories(libifm_libverto_s
        PUBLIC ${libifm_verto_incs}
        )
    
    set_target_properties(libifm_libverto_s PROPERTIES PREFIX "")
    set_target_properties(libifm_libverto_s PROPERTIES OUTPUT_NAME libifm_libverto)

    # install all files
    install(TARGETS libifm_libverto
        LIBRARY DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
    install(TARGETS libifm_libverto_s
        ARCHIVE DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
        install(FILES verto/ifm_verto.h DESTINATION ${INCLUDE_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)
endif()
