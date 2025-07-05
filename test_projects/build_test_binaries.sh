#!/bin/bash

echo "Building test binaries for binary comparison feature..."

# Check if GCC is available
if ! command -v gcc &> /dev/null; then
    echo "ERROR: GCC not found. Please install GCC."
    exit 1
fi

echo "Compiling Version 1..."
gcc -o binary_compare_v1 binary_compare_v1.c -Wall
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to compile Version 1."
    exit 1
fi

echo "Compiling Version 2..."
gcc -o binary_compare_v2 binary_compare_v2.c -Wall
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to compile Version 2."
    exit 1
fi

echo "Build completed successfully!"
echo
echo "The following binaries were created:"
echo "- binary_compare_v1"
echo "- binary_compare_v2"
echo
echo "You can now upload these files to test the binary comparison feature."

# Make the binaries executable
chmod +x binary_compare_v1 binary_compare_v2 