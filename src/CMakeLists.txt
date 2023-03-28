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

set(check_libs
    ${LIBNETTLE_LIBRARY}
    )

list(REMOVE_DUPLICATES check_incs)
list(REMOVE_DUPLICATES check_libs)

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
