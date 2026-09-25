@echo off
echo Alpha>input.txt
echo beta>>input.txt
echo alphabet>>input.txt
type input.txt | findstr /i "alpha" | find /v "alphabet" | sort
for /F "tokens=1" %%A in (input.txt) do echo token-%%A
where input.txt
