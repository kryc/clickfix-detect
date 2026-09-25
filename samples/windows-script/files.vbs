Dim fso, output
Set fso = CreateObject("Scripting.FileSystemObject")
Set output = fso.CreateTextFile("C:\Users\Public\clickfix-benign.txt", True)
output.WriteLine "benign virtual file"
output.Close
WScript.Echo "created virtual sample"
