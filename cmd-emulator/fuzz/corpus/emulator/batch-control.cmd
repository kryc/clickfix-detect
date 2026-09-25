set VALUE=abcdef
call :sub first second
if defined VALUE for /L %%N in (1,1,3) do echo %%N-%VALUE:~1,3%
goto :eof
:sub
shift
echo %~nx1
exit /b 0
