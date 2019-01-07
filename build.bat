@echo off
set O=co2_reader.exe
cl -Fe:%O% src/co2_unit.c -Ideps\hidapi\hidapi deps\hidapi\windows\hid.c setupapi.lib hid.lib -DWIN32 -Z7 -nologo
echo PROGRAM	%O%
