#!/bin/bash

echo "======================================="
echo "Setare Mediu Python - Semnatura Digitala PDF Pro (Linux)"
echo "======================================="

echo "1. Instalare dependinte de sistem (poate necesita parola sudo)..."
# Tkinter e necesar pentru GUI. Instalăm python3-venv pentru a putea crea un mediu izolat.
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv python3-tk

echo ""
echo "2. Creare mediu virtual (python_env)..."
if [ ! -d "python_env" ]; then
    python3 -m venv python_env
    if [ $? -ne 0 ]; then
        echo "[EROARE] Nu s-a putut crea mediul virtual."
        exit 1
    fi
else
    echo "[INFO] Mediul virtual exista deja."
fi

echo ""
echo "3. Activare mediu virtual si actualizare pip..."
source python_env/bin/activate
python3 -m pip install --upgrade pip

echo ""
echo "4. Instalare librarii necesare pentru aplicatie..."
python3 -m pip install Pillow PyMuPDF tkinterdnd2 PyKCS11 endesive cryptography

echo ""
echo "======================================="
echo "Instalare finalizata cu succes!"
echo "Puteti porni aplicatia folosind: ./pdf-e-sign.sh"
echo "======================================="
