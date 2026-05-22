#!/bin/bash

# Fortam scriptul sa ruleze din folderul in care se afla
cd "$(dirname "$0")"

# Verificam daca exista mediul virtual instalat
if [ ! -d "python_env" ]; then
    echo "[EROARE] Mediul virtual 'python_env' nu a fost gasit."
    echo "Va rugam sa rulati mai intai scriptul de instalare: ./install.sh"
    exit 1
fi

# Activam mediul si pornim aplicatia
source python_env/bin/activate
python3 pdf-e-sign.py
