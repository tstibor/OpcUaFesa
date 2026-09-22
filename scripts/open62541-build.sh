#!/bin/bash

YOCTO_VERSION="yocto-5"
OPEN62541_BRANCH="1.5"
OPEN62541_ENCRYPTION="OFF"

# Display help menu
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -e, --encryption=TYPE   Set encryption engine (OFF, MBEDTLS, OPENSSL, LIBRESSL). Default: OFF"
    echo "  -h, --help              Display this help message and exit"
    exit 0
}

# Parse command-line arguments
for arg in "$@"; do
    case $arg in
        -e=*|--encryption=*)
            OPEN62541_ENCRYPTION="${arg#*=}"
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Unknown option: $arg"
            show_help
            ;;
    esac
done

# Convert value to uppercase for CMake consistency
OPEN62541_ENCRYPTION=$(echo "${OPEN62541_ENCRYPTION}" | tr '[:lower:]' '[:upper:]')

# Validate allowed options
case "${OPEN62541_ENCRYPTION}" in
    OFF|MBEDTLS|OPENSSL|LIBRESSL) ;;
    *)
        echo "Error: Invalid encryption option '${OPEN62541_ENCRYPTION}'."
        echo "Allowed values: OFF, MBEDTLS, OPENSSL, LIBRESSL"
        exit 1
        ;;
esac

source /common/usr/embedded/yocto/fesa/current/sdk/environment-setup-core2-64-ffos-linux

TMP_DIR=$(mktemp -d /tmp/open62541-XXXXX)
trap 'rm -rf "${TMP_DIR}"' EXIT

cd "${TMP_DIR}"

echo "Building in path ${TMP_DIR}"
git clone --branch ${OPEN62541_BRANCH} --recursive https://github.com/open62541/open62541.git
cd open62541 && mkdir build && cd build

cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=$OECMAKE_TOOLCHAIN_FILE \
    -DCMAKE_INSTALL_PREFIX=$HOME/install/open62541/${YOCTO_VERSION}/${OPEN62541_BRANCH} \
    -DUA_ENABLE_AMALGAMATION=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    -DUA_BUILD_EXAMPLES=OFF \
    -DUA_ENABLE_ENCRYPTION=${OPEN62541_ENCRYPTION} \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON

cmake --build . -- -j$(nproc)
cmake --build . --target install
