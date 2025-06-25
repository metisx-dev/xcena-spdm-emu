#!/bin/bash

# Default values
arch="x64"
toolchain="GCC"
target="Debug"
crypto="openssl"

# Create build directory if it doesn't exist
if [ ! -d "build" ]; then
    mkdir build
fi
cd build

# Configure CMake
cmake -DARCH=$arch -DTOOLCHAIN=$toolchain -DTARGET=$target -DCRYPTO=$crypto ..

# Copy sample key
make copy_sample_key

# Build the project
make -j8 clean