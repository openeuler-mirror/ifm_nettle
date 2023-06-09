message("${BoldGreen}---- Selected options begin ----${ColourReset}")

option(ENABLE_GCOV "set ifm_nettle gcov option" OFF)
if (ENABLE_GCOV STREQUAL "ON")
    message("${Green}--  Enable gcov${ColourReset}")
endif()

option(ENABLE_LIBIFM_NETTLE "enable ifm_nettle libifm_nettle option" ON)
if (ENABLE_LIBIFM_NETTLE STREQUAL "ON")
    add_definitions(-DENABLE_LIBIFM_NETTLE=1)
    set(ENABLE_LIBIFM_NETTLE 1)
    message("${Green}--  Enable libifm_nettle${ColourReset}")
endif()

option(ENABLE_LIBIFM_LIBGCRYPT "enable ifm_libgcrypt libifm_libgcrypt option" ON)
if (ENABLE_LIBIFM_LIBGCRYPT STREQUAL "ON")
    add_definitions(-DENABLE_LIBIFM_LIBGCRYPT=1)
    set(ENABLE_LIBIFM_LIBGCRYPT 1)
    message("${Green}--  Enable libifm_libgcrypt${ColourReset}")
endif()

option(ENABLE_LIBIFM_LIBXCRYPT "enable ifm_libxcrypt libifm_libxcrypt option" ON)
if (ENABLE_LIBIFM_LIBXCRYPT STREQUAL "ON")
    add_definitions(-DENABLE_LIBIFM_LIBXCRYPT=1)
    set(ENABLE_LIBIFM_LIBXCRYPT 1)
    message("${Green}--  Enable libifm_libxcrypt${ColourReset}")
endif()

message("${BoldGreen}---- Selected options end ----${ColourReset}")
