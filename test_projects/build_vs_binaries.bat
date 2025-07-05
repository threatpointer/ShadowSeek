@echo off
echo Building test binaries for binary comparison feature using Visual Studio...

REM Set path to Visual Studio installation
set VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community

REM Check if Visual Studio exists at the specified path
if not exist "%VS_PATH%" (
    echo ERROR: Visual Studio not found at %VS_PATH%
    exit /b 1
)

REM Use the Visual Studio Developer Command Prompt
echo Setting up Visual Studio environment...
call "%VS_PATH%\Common7\Tools\VsDevCmd.bat" -no_logo

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