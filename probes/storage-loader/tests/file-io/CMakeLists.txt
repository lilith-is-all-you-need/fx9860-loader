cmake_minimum_required(VERSION 3.15)
project(FlashIoCheck C ASM)
include(GenerateG1A)
add_executable(io_check check.c calls.S)
target_compile_options(io_check PRIVATE -m4-nofpu -Os -ffreestanding -fno-builtin -Wall -Wextra -Werror)
target_link_options(io_check PRIVATE -m4-nofpu -T "${CMAKE_CURRENT_SOURCE_DIR}/guest.ld")
generate_g1a(TARGET io_check OUTPUT "IOCheck.g1a" NAME "IOCheck" INTERNAL "@IOCHECK"
             ICON "icon.png")
