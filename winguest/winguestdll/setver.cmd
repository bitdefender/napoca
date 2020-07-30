@echo off

if "%3"=="" goto usage

set TOOLS_PATH=..\_tools

FOR /F %%i in (buildnumber) do @set buildnumber=%%i

echo Setting MDEICAR version:    %1.%2.%3.%buildnumber%

:: REM for %%f in (*.c)   do %TOOLS_PATH%\prjver %%f "//   Version      : " %1 %2 %3 /t4
:: REM for %%f in (*.h)   do %TOOLS_PATH%\prjver %%f "//   Version      : " %1 %2 %3 /t4
:: for %%f in (*.txt) do %TOOLS_PATH%\prjver %%f "   Version      : " %1 %2 %3 /t4 >nul

%TOOLS_PATH%\prjver version.h "#define MDEICAR_VERSION_HIGH        " %1 >nul
%TOOLS_PATH%\prjver version.h "#define MDEICAR_VERSION_LOW         " %2 >nul
%TOOLS_PATH%\prjver version.h "#define MDEICAR_VERSION_REVISION    " %3 >nul
%TOOLS_PATH%\prjver version.h "#define MDEICAR_VERSION_BUILD       " %buildnumber% >nul

goto exit

:usage
echo.
echo usage: setver hiversion loversion revision
echo.
echo example: setver 0 1 123
echo.
goto exit

:exit
