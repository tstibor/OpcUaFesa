cmake_minimum_required(VERSION 3.18) # gtest_discover_tests(... DISCOVERY_MODE PRE_TEST) below
project(OpcUaFesa CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# When cross-compiling for the FESA yocto target (core2-64-ffos-linux, via a
# build-yocto/ directory configured after sourcing
# environment-setup-core2-64-ffos-linux - see the README's "Cross-Building
# for the FESA Yocto Target" section), the test binary normally has to be
# deployed to the actual target to run. Enabling this option instead links
# it so it can also run directly on this dev host.
#   - PT_INTERP is set to the SDK's *native* loader
#     (sysroots/x86_64-ffossdk-linux/.../ld-linux-x86-64.so.2), which is
#     built to run on a wide range of host distros - unlike the host's own
#     loader, which may not understand symbol versions the cross-compiled
#     binary needs.
#   - RPATH (not RUNPATH - see --disable-new-dtags below) points at the
#     *target* sysroot's lib dirs, so the native loader still resolves
#     libc/libstdc++/etc. to the exact versions the binary was actually
#     linked against, not whatever the host happens to have installed.
# No qemu or chroot involved - this is plain dynamic linking, just pointed
# at the SDK sysroot instead of the host's own.  Off by default (mirroring
# the Makefile): a build-yocto/ build defaults to producing a
# target-only binary, same as before this option existed.
option(OPCUA_FESA_RUN_ON_HOST
    "When cross-compiling for the FESA yocto target, link opcua_client_tests with an explicit dynamic linker + rpath into the yocto SDK sysroot so it can also run (and be ctest'd) directly on this host. No effect on a normal host-native build."
    OFF)

if(OPCUA_FESA_RUN_ON_HOST)
    if(NOT DEFINED ENV{SDKTARGETSYSROOT})
        message(FATAL_ERROR
            "OPCUA_FESA_RUN_ON_HOST=ON requires the yocto SDK environment to "
            "be sourced before running cmake (SDKTARGETSYSROOT is not set) - "
            "source environment-setup-core2-64-ffos-linux first, see the "
            "README's Cross-Building section.")
    endif()

    set(_opcua_fesa_target_sysroot "$ENV{SDKTARGETSYSROOT}")
    get_filename_component(_opcua_fesa_sysroots_dir "${_opcua_fesa_target_sysroot}" DIRECTORY)
    set(_opcua_fesa_dynamic_linker "${_opcua_fesa_sysroots_dir}/x86_64-ffossdk-linux/lib/ld-linux-x86-64.so.2")
    set(_opcua_fesa_rpath "${_opcua_fesa_target_sysroot}/usr/lib:${_opcua_fesa_target_sysroot}/lib")

    if(NOT EXISTS "${_opcua_fesa_dynamic_linker}")
        message(FATAL_ERROR "OPCUA_FESA_RUN_ON_HOST=ON: expected native SDK loader not found at ${_opcua_fesa_dynamic_linker}")
    endif()

    set(OPCUA_FESA_HOST_RUN_LINK_OPTIONS
        "-Wl,-dynamic-linker,${_opcua_fesa_dynamic_linker}"
        "-Wl,-rpath,${_opcua_fesa_rpath}"
        "-Wl,--disable-new-dtags"
    )
endif()

# Find open62541 dependency
find_package(open62541 REQUIRED)

# Header-only library target
add_library(OpcUaFesa INTERFACE)
target_include_directories(OpcUaFesa INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(OpcUaFesa INTERFACE open62541::open62541)

# Fetch GoogleTest
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.15.2
)
FetchContent_MakeAvailable(googletest)

# Test Executable
enable_testing()
add_executable(opcua_client_tests tests/test_opcua_client.cpp)
target_link_libraries(opcua_client_tests
    PRIVATE
    OpcUaFesa
    GTest::gtest_main
)
if(OPCUA_FESA_RUN_ON_HOST)
    target_link_options(opcua_client_tests PRIVATE ${OPCUA_FESA_HOST_RUN_LINK_OPTIONS})
endif()
# Lets the security tests locate scripts/certs/*.der/*.pem regardless of the
# working directory the test binary is invoked from (direct run vs ctest).
target_compile_definitions(opcua_client_tests PRIVATE
    OPCUA_FESA_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
)

# Registers one CTest test per GoogleTest TEST/TEST_F (e.g.
# "OpcUaClientSecurityTest.AnonymousConnectWithSignAndEncryptSucceeds"), so
# `ctest -R <suite-or-test-name>` and `ctest -N` work as expected - a single
# add_test(COMMAND opcua_client_tests) would register only one CTest test
# for the whole binary, which -R can never match against an individual
# GoogleTest suite/case name.
#
# DISCOVERY_MODE PRE_TEST (rather than the default POST_BUILD) defers
# running the binary (with --gtest_list_tests, to enumerate the test names)
# until `ctest` actually runs, instead of doing it as a post-build step.
# This matters for the FESA yocto cross-build (see the README's
# "Cross-Building for the FESA Yocto Target" section): POST_BUILD would try
# to execute the cross-compiled binary on the host as part of `cmake --build
# .` itself, which fails for a target-only build (OPCUA_FESA_RUN_ON_HOST
# unset/OFF) since that binary isn't host-executable. PRE_TEST keeps the
# build itself working either way; only actually running `ctest` requires a
# host-executable binary (i.e. OPCUA_FESA_RUN_ON_HOST=ON, or the plain
# host-native build), exactly as before this change.
include(GoogleTest)
gtest_discover_tests(opcua_client_tests
    DISCOVERY_MODE PRE_TEST
)
