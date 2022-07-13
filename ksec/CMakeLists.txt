cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

project(driver VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_definitions(-D__KERNEL__ -DMODULE)

execute_process(
        COMMAND uname -r
        OUTPUT_VARIABLE KERNEL_RELEASE
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

find_path(
        KERNELHEADERS_DIR
        include/linux/user.h
        PATHS /usr/src/linux-lts
)

include_directories(
        ${KERNELHEADERS_DIR}/include
)

set(DRIVER_FILE ksec.ko)
set(KBUILD_CMD $(MAKE) -C ${KERNELHEADERS_DIR} modules M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR})

FILE(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "obj-m := ksec.o")

add_custom_command(OUTPUT ${DRIVER_FILE}
        COMMAND ${KBUILD_CMD}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS ksec.c VERBATIM)

add_custom_target(driver ALL DEPENDS ${DRIVER_FILE})
add_library(dummy_target ksec.c)
