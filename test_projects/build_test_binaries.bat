@echo off
echo Building test binaries for binary comparison feature...

REM Check if GCC is available
where gcc >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: GCC not found in PATH. Please install MinGW or GCC.
    exit /b 1
)

echo Compiling Version 1...
gcc -o binary_compare_v1.exe binary_compare_v1.c -Wall
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to compile Version 1.
    exit /b 1
)

echo Compiling Version 2...
gcc -o binary_compare_v2.exe binary_compare_v2.c -Wall
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to compile Version 2.
    exit /b 1
)

echo Build completed successfully!
echo.
echo The following binaries were created:
echo - binary_compare_v1.exe
echo - binary_compare_v2.exe
echo.
echo You can now upload these files to test the binary comparison feature. 