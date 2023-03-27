message("${BoldGreen}---- Selected options begin ----${ColourReset}")

option(ENABLE_GCOV "set lcr gcov option" OFF)
if (ENABLE_GCOV STREQUAL "ON")
    message("${Green}--  Enable gcov${ColourReset}")
endif()

option(ENABLE_LIBIFM_NETTLE "enable lcr liblcr option" ON)
if (ENABLE_LIBIFM_NETTLE STREQUAL "ON")
    add_definitions(-DENABLE_LIBIFM_NETTLE=1)
    set(ENABLE_LIBIFM_NETTLE 1)
    message("${Green}--  Enable liblcr${ColourReset}")
endif()

message("${BoldGreen}---- Selected options end ----${ColourReset}")
