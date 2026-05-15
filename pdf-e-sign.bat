@echo off
title PDF Batch Signer
echo Se porneste aplicatia...
:: Ruleaza scriptul folosind interpretorul portabil, nu cel din sistem
start "" ".\python_env\python.exe" "pdf-e-sign.py"
exit