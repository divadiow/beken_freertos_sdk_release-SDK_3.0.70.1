@echo off
@REM generate_sys_config alias_project_name targe_sys_config
@REM example: 
@REM generate_sys_config bk7231u config\sys_config.h

if "%2" equ "" (
set old_sys_config=config\sys_config.h
)

if not exist config (
	mkdir config
)

if "%1" equ "bk7231u" (
set new_sys_config=beken378\app\config\sys_config_bk7231u.h
goto update_sys_config
)
if "%1" equ "bk7231n" (
set new_sys_config=beken378\app\config\sys_config_bk7231n.h
goto update_sys_config
)
if "%1" equ "bk7251" (
set new_sys_config=beken378\app\config\sys_config_bk7251.h
goto update_sys_config
)
if "%1" equ "bk7238" (
set new_sys_config=beken378\app\config\sys_config_bk7238.h
goto update_sys_config
)
if "%1" equ "bk7231" (
set new_sys_config=beken378\app\config\sys_config_bk7231.h
goto update_sys_config
)
if "%1" equ "" (
set new_sys_config=beken378\app\config\sys_config_bk7231u.h
goto update_sys_config
)

set new_sys_config=beken378\app\config\%1.h


:update_sys_config

set new_hash=
set old_hash=

setlocal enabledelayedexpansion

if exist %new_sys_config% (
	for /f "eol=C skip=1 tokens=*" %%i in ('certutil -hashfile %new_sys_config% MD5') do set new_hash=!new_hash!%%i
	set new_hash=!new_hash: =!
	echo hash^(%new_sys_config%^)=!new_hash!
) else (
    echo %new_sys_config% not exist!
	goto :EOF
)
if exist %old_sys_config% (
	for /f "eol=C skip=1 tokens=*" %%i in ('certutil -hashfile %old_sys_config% MD5') do set old_hash=!old_hash!%%i
	set old_hash=!old_hash: =!
	echo hash^(%old_sys_config%^)=!old_hash!
)

if !new_hash! neq !old_hash! (
	copy %new_sys_config% %old_sys_config% /Y
)

echo "  %GREEN%GEN  .config%NC%"
echo #include "config/sys_config.h" > config.c
tools\\gnuwin32\\sed.exe -n "/^#define/p" config/sys_config.h | tools\\gnuwin32\\awk.exe "{print $2}" | sort.exe | tools\\gnuwin32\\uniq.exe | tools\\gnuwin32\\awk.exe "{print """valueOf_"""$1"""="""$1}" >> config.c
echo # Autogenerated by Makefile, DON'T EDIT > .config
%ARM_GCC_TOOLCHAIN%arm-none-eabi-gcc -E config.c | tools\\gnuwin32\\grep.exe "^valueOf_" | tools\\gnuwin32\\sed.exe "s/valueOf_//" >> .config
tools\\gnuwin32\\sed.exe -i "/_SYS_CONFIG_H_/d" .config
rm -f config.c

endlocal
