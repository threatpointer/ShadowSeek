@echo off
echo Compiling test binaries for binary comparison feature...

echo Compiling Version 1...
cl /nologo /W4 /EHsc /Fe:binary_compare_v1.exe binary_compare_v1.c
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to compile Version 1.
    exit /b 1
)

echo Compiling Version 2...
cl /nologo /W4 /EHsc /Fe:binary_compare_v2.exe binary_compare_v2.c
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to compile Version 2.
    exit /b 1
)

echo Cleaning up object files...
del *.obj

echo Build completed successfully!
echo.
echo The following binaries were created:
echo - binary_compare_v1.exe
echo - binary_compare_v2.exe
echo.
echo You can now upload these files to test the binary comparison feature. 