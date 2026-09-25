echo Alpha>input.txt
echo beta>>input.txt
type input.txt | findstr /i "alpha" | sort
for /F "tokens=1" %%A in (input.txt) do echo %%A
