set "path=%path%;C:\mingw64\bin"
cd /d "%~dp0"

call _clean.cmd
mingw32-make -f Makefile all
