#!/bin/bash

# Default values
ARCH="x64"
TOOLCHAIN="GCC"
TARGET="Debug"
CRYPTO="openssl"

# Create build directory if it doesn't exist
if [ ! -d "build" ]; then
    mkdir build
fi
cd build

# Configure CMake
cmake -DARCH=$ARCH \
    -DTOOLCHAIN=$TOOLCHAIN \
    -DTARGET=$TARGET \
    -DCRYPTO=$CRYPTO \
    ..

# Copy sample key
make copy_sample_key

# Build the project
make -j8 spdm_device_validator_sample