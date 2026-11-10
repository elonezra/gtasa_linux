cmake_minimum_required(VERSION 3.20)
project(gtasa_linux C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
option(GTASA_DEBUG_LOG "Write the compatibility debug log" OFF)
option(GTASA_QUIT_CHORD "Enable the Guide/Back + Start quit chord" ON)
option(GTASA_FREE_AIM "Enable the D-pad Down free-aim latch (v2.11.311-validated gameplay patch)" OFF)
option(GTASA_SDL2_SHIM "Build against the SDL3-to-system-SDL2 runtime shim" OFF)
set(GTASA_PRODUCT_NAME "Grand Theft Auto: San Andreas" CACHE STRING "Window and fatal-error product name")
set(GTASA_CONFIG_NAME "gtasa_nx.cfg" CACHE STRING "Wrapper configuration filename")
set(GTASA_APPSTATE_NAME "appstate.txt" CACHE STRING "Wrapper app-state filename")
set(GAME_BINARY_NAME "gtasa_linux" CACHE STRING "Game executable target and output name")


find_package(PkgConfig REQUIRED)
pkg_check_modules(SDL3 REQUIRED IMPORTED_TARGET sdl3)
pkg_check_modules(EGL REQUIRED IMPORTED_TARGET egl)
pkg_check_modules(GLES2 REQUIRED IMPORTED_TARGET glesv2)
pkg_check_modules(OPENAL REQUIRED IMPORTED_TARGET openal)
pkg_check_modules(MPG123 REQUIRED IMPORTED_TARGET libmpg123)

add_executable(${GAME_BINARY_NAME}
    source/bionic_tls.c
    source/aml_mod.c
    source/config.c
    source/error_linux.c
    source/imports.c
    source/input_linux.c
    source/jni_fake.c
    source/libc_shim.c
    source/main_linux.c
    source/overlay.c
    source/so_util.c
    source/util.c
    source/hooks/game_linux.c
    source/audio_linux.c
)

target_include_directories(${GAME_BINARY_NAME} PRIVATE source source/hooks)
target_link_libraries(${GAME_BINARY_NAME} PRIVATE
    PkgConfig::SDL3
    PkgConfig::EGL
    PkgConfig::GLES2
    PkgConfig::OPENAL
    PkgConfig::MPG123
    m dl pthread
)

target_compile_definitions(${GAME_BINARY_NAME} PRIVATE
    _GNU_SOURCE
    GTASA_PRODUCT_NAME="${GTASA_PRODUCT_NAME}"
    GTASA_CONFIG_NAME="${GTASA_CONFIG_NAME}"
    GTASA_APPSTATE_NAME="${GTASA_APPSTATE_NAME}"

)
if(GTASA_DEBUG_LOG)
    target_compile_definitions(${GAME_BINARY_NAME} PRIVATE DEBUG_LOG=1)
endif()
if(GTASA_QUIT_CHORD)
    target_compile_definitions(${GAME_BINARY_NAME} PRIVATE GTASA_QUIT_CHORD=1)
endif()
if(GTASA_FREE_AIM)
    target_compile_definitions(${GAME_BINARY_NAME} PRIVATE GTASA_FREE_AIM=1)
endif()
target_compile_options(${GAME_BINARY_NAME} PRIVATE -Wall -Wextra -Wno-unused-parameter)

# Free-aim trampoline is AArch64 assembly. Host (x86_64) builds skip it and
# use the weak NULL refs in game_linux.c; the pure-C IsFreeAimMode /
# IsLockOnMode hooks still apply there at the source level.
if(GTASA_FREE_AIM AND CMAKE_SYSTEM_PROCESSOR MATCHES "[Aa][Aa][Rr][Cc][Hh]64|[Aa][Rr][Mm]64")
  enable_language(ASM)
  target_sources(${GAME_BINARY_NAME} PRIVATE source/hooks/free_aim_stub.s)
endif()

install(TARGETS ${GAME_BINARY_NAME} RUNTIME DESTINATION bin)

include(CTest)
if(BUILD_TESTING)
    add_executable(elf_pages_test tests/elf_pages_test.c source/so_util.c source/bionic_tls.c source/error_linux.c)
    target_link_libraries(elf_pages_test PRIVATE pthread)
    target_include_directories(elf_pages_test PRIVATE source)
    target_compile_definitions(elf_pages_test PRIVATE _GNU_SOURCE)
    target_compile_options(elf_pages_test PRIVATE -Wall -Wextra -UNDEBUG)
    add_test(NAME elf_pages COMMAND elf_pages_test)
    set_tests_properties(elf_pages PROPERTIES TIMEOUT 10)
    add_executable(bionic_tls_test tests/bionic_tls_test.c source/bionic_tls.c source/so_util.c source/error_linux.c)
    target_include_directories(bionic_tls_test PRIVATE source)
    target_compile_definitions(bionic_tls_test PRIVATE _GNU_SOURCE)
    target_compile_options(bionic_tls_test PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(bionic_tls_test PRIVATE pthread)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "[Aa][Aa][Rr][Cc][Hh]64|[Aa][Rr][Mm]64")
        enable_language(ASM)
        target_sources(bionic_tls_test PRIVATE tests/bionic_tls_fixture.S)
    endif()
    add_test(NAME bionic_tls COMMAND bionic_tls_test)
    set_tests_properties(bionic_tls PROPERTIES TIMEOUT 10)
    add_executable(input_linux_test tests/input_linux_test.c source/input_linux.c)
    target_include_directories(input_linux_test PRIVATE source)
    target_link_libraries(input_linux_test PRIVATE PkgConfig::SDL3 m)
    if(GTASA_QUIT_CHORD)
        target_compile_definitions(input_linux_test PRIVATE GTASA_QUIT_CHORD=1)
    endif()
    target_compile_options(input_linux_test PRIVATE -Wall -Wextra -UNDEBUG)
    add_test(NAME input_linux COMMAND input_linux_test)
    set_tests_properties(input_linux PROPERTIES TIMEOUT 10)
    if(NOT GTASA_SDL2_SHIM)
        add_executable(audio_linux_test tests/audio_linux_test.c source/audio_linux.c)
        target_include_directories(audio_linux_test PRIVATE source)
        target_link_libraries(audio_linux_test PRIVATE PkgConfig::SDL3 PkgConfig::OPENAL m pthread)
        target_compile_options(audio_linux_test PRIVATE -Wall -Wextra -UNDEBUG)
        add_test(NAME audio_linux COMMAND audio_linux_test)
        set_tests_properties(audio_linux PROPERTIES ENVIRONMENT "SDL_AUDIO_DRIVER=dummy" TIMEOUT 10)
    endif()
endif()
