@echo off
if "%1"=="" (set INPUT=sample) else (set INPUT=%1)
call :show first second
echo input=%INPUT% result=%RESULT%
for /L %%N in (1,1,3) do echo iteration-%%N
goto :eof

:show
echo arguments=%1,%2
shift
set RESULT=%1
exit /b 0
