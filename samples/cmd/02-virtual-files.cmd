@echo off
md demo
cd demo
echo first>notes.txt
echo second>>notes.txt
type notes.txt
copy notes.txt copy.txt
ren copy.txt renamed.txt
