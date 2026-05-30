@echo off
:: Fortam terminalul sa foloseasca folderul curent (repara problema Run as Administrator)
cd /d "%~dp0"
chcp 65001 >nul

echo =======================================
echo Setare Mediu Python (Portabil) - Semnatura Digitala PDF Pro
echo =======================================

set "PYTHON_DIR=python_env"
set "URL=https://github.com/winpython/winpython/releases/download/16.6.20250620final/Winpython64-3.12.10.1dot.zip"
set "ZIP_FILE=winpython.zip"

echo 1. Verificare mediu Python portabil...
IF EXIST ".\%PYTHON_DIR%\python.exe" GOTO skip_download

echo [INFO] Folderul python_env nu exista. Incepem descarcarea automata WinPython...
echo Aceasta operatiune poate dura cateva minute in functie de viteza de internet.
echo.

curl --ssl-no-revoke -L -o "%ZIP_FILE%" "%URL%"

IF NOT EXIST "%ZIP_FILE%" (
    echo [EROARE] Descarcarea a esuat. Verificati conexiunea la internet sau link-ul.
    pause
    exit /b
)

echo.
echo [INFO] Extragere arhiva... ^(va rugam asteptati, poate dura putin^)
rem Curatam fisierele temporare daca a mai rulat inainte
if exist .\wp_temp rmdir /s /q .\wp_temp
powershell -ExecutionPolicy Bypass -command "Expand-Archive -Path '%ZIP_FILE%' -DestinationPath '.\wp_temp' -Force"

echo.
echo [INFO] Cautare motor Python in arhiva extrasa...
if exist ".\%PYTHON_DIR%" rmdir /s /q ".\%PYTHON_DIR%"

set "PY_DIR="
for /f "delims=" %%F in ('dir /s /b .\wp_temp\python.exe 2^>nul') do (
    set "PY_DIR=%%~dpF"
    goto found_py
)
:found_py

IF NOT DEFINED PY_DIR (
    echo [EROARE] Nu s-a gasit executabilul python.exe in interiorul arhivei!
    rmdir /s /q .\wp_temp
    del "%ZIP_FILE%"
    pause
    exit /b
)

rem Taiem ultimul slash de la calea folderului gasit pentru a-l putea muta
set "PY_DIR=%PY_DIR:~0,-1%"

echo [INFO] Redenumire automata folder in %PYTHON_DIR%...
move "%PY_DIR%" ".\%PYTHON_DIR%" >nul

rem Curatenie resturi
rmdir /s /q .\wp_temp
del "%ZIP_FILE%"

IF NOT EXIST ".\%PYTHON_DIR%\python.exe" (
    echo [EROARE] Mutarea nu a reusit sa creeze folderul %PYTHON_DIR%.
    pause
    exit /b
)
echo [OK] Mediul portabil a fost instalat cu succes!

:skip_download
echo [OK] Mediul portabil Python este pregatit.
echo.
echo 2. Actualizare pip ^(folosind Python portabil^)...
".\%PYTHON_DIR%\python.exe" -m pip install --upgrade pip

echo.
echo 3. Instalare librarii necesare pentru aplicatie...
".\%PYTHON_DIR%\python.exe" -m pip install Pillow PyMuPDF tkinterdnd2 PyKCS11 endesive cryptography attrs

echo.
echo =======================================
echo Instalare finalizata cu succes!
echo Gata! Poti porni aplicatia!
echo =======================================
pause