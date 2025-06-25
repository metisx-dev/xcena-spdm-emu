cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

set(src_spdm_transport_xcena_lib
    common.c
    none.c
)

add_library(spdm_transport_xcena_lib STATIC ${src_spdm_transport_xcena_lib})
