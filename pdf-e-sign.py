import tkinter as tk
from tkinter import ttk, filedialog, messagebox, colorchooser
import threading
import os
import logging
import datetime
import traceback
import json
import platform
from pathlib import Path
from dataclasses import dataclass
from typing import Tuple
from PIL import Image, ImageTk
import fitz  # PyMuPDF
from tkinterdnd2 import DND_FILES, TkinterDnD

import PyKCS11
from endesive.pdf import cms
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# --- PLATFORMĂ ---
IS_WINDOWS = platform.system() == "Windows"

# --- CONFIGURARE LOGGING ---
logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

if logger.hasHandlers():
    logger.handlers.clear()

file_handler = logging.FileHandler("app_debug.log", encoding="utf-8", mode='w')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

SETTINGS_FILE = "signature_settings.json"

DEFAULT_SETTINGS = {
    "contact": "",
    "location": "România",
    "reason": "Aprobat",
    "bg_color": "#ffffff",
    "outline_color": "#000000",
    "border": 1,
    "display_cn": True,
    "display_date": True,
    "display_reason": True,
    "display_location": False,
    "display_contact": False,
    "fontsize": 8,
    "textalign": "left",
    "linespacing": 1.2,
    "lbl_cn": "",
    "lbl_date": "",
    "lbl_reason": "Motiv:",
    "lbl_loc": "",
    "lbl_contact": "",
    "use_image": False,
    "image_path": ""
}

# --- PROFILURI DRIVERE PKCS#11 ---
if IS_WINDOWS:
    DLL_PRESETS = {
        "Alfasign / SafeNet (eToken.dll)": r"C:\Windows\System32\eToken.dll",
        "DigiSign / SafeNet (eToken.dll)": r"C:\Windows\System32\eToken.dll",
        "DigiSign / ePass2003 (eps2003csp11.dll)": r"C:\Windows\System32\eps2003csp11.dll",
        "certSign / SafeNet (eToken.dll)": r"C:\Windows\System32\eToken.dll",
        "certSIGN / Athena (acpkcs211.dll)": r"C:\Windows\System32\acpkcs211.dll",
        "certSIGN / Bit4Id (bit4xpki.dll)": r"C:\Windows\System32\bit4xpki.dll",
        "certSIGN / Oberthur (OcsCryptoki.dll)": r"C:\Windows\System32\OcsCryptoki.dll",
        "CertDigital / Bit4Id (bit4xpki.dll)": r"C:\Windows\System32\bit4xpki.dll"
    }
    DEFAULT_DLL = "Alfasign / SafeNet (eToken.dll)"
else:
    # Linux / Ubuntu
    DLL_PRESETS = {
        "Alfasign / SafeNet (libeToken.so)":       "/usr/lib/libeToken.so",
        "DigiSign / SafeNet (libeToken.so)":        "/usr/lib/libeToken.so",
        "DigiSign / ePass2003 (libepsng_p11.so)":   "/usr/lib/libepsng_p11.so",
        "certSIGN / Athena (libacpkcs211.so)":      "/usr/lib/libacpkcs211.so",
        "certSIGN / Bit4Id (libbit4xpki.so)":       "/usr/lib/libbit4xpki.so",
        "certSIGN / Oberthur (libocscryptoki.so)":  "/usr/lib/libocscryptoki.so",
        "CertDigital / Bit4Id (libbit4xpki.so)":    "/usr/lib/libbit4xpki.so",
        "OpenSC (opensc-pkcs11.so)":                "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    }
    DEFAULT_DLL = "Alfasign / SafeNet (libeToken.so)"

def hex_to_rgb(hex_str):
    hex_str = hex_str.lstrip('#')
    if len(hex_str) != 6: return [0.0, 0.0, 0.0]
    return [int(hex_str[i:i+2], 16) / 255.0 for i in (0, 2, 4)]

class HardwareTokenHSM:
    """Gestionarea Hardware-ului (PKCS#11) cu suport Universal Multi-Token"""
    
    @staticmethod
    def list_all_certificates(dll_path):
        if not os.path.exists(dll_path):
            raise FileNotFoundError(f"Fișierul driver nu a fost găsit la: {dll_path}")

        pkcs11 = PyKCS11.PyKCS11Lib()
        try:
            pkcs11.load(dll_path)
        except Exception as e:
            raise Exception(f"Eroare la încărcarea driver-ului: {e}")
        
        slots = pkcs11.getSlotList(tokenPresent=True)
        if not slots:
            raise Exception("Nu s-a detectat niciun token USB conectat valid pentru acest driver!")
        
        certs_info = []
        for slot in slots:
            try:
                token_info = pkcs11.getTokenInfo(slot)
                label = token_info.label.strip() if isinstance(token_info.label, str) else str(token_info.label)
                
                session = pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION)
                certs = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
                
                for cert in certs:
                    cka_id = session.getAttributeValue(cert, [PyKCS11.CKA_ID])[0]
                    cert_val = session.getAttributeValue(cert, [PyKCS11.CKA_VALUE])[0]
                    cert_bytes = bytes(cert_val)
                    
                    try:
                        cert_obj = x509.load_der_x509_certificate(cert_bytes, default_backend())
                        cn = cert_obj.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                    except:
                        cn = "Certificat Necunoscut"

                    certs_info.append({
                        'slot': slot,
                        'token_label': label,
                        'cka_id': tuple(cka_id),
                        'cn': cn,
                        'cert_der': cert_bytes
                    })
                session.closeSession()
            except Exception as e:
                logging.warning(f"Eroare citire slot {slot}: {e}")
                
        return certs_info

    def __init__(self, dll_path, pin, target_slot, target_cka_id):
        logging.info(f"--- INIȚIALIZARE HSM PE SLOTUL {target_slot} ---")
        
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(dll_path)
            
        self.session = self.pkcs11.openSession(target_slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
        try:
            self.session.login(pin)
            logging.info("Autentificare hardware reușită pe token-ul țintă!")
        except PyKCS11.PyKCS11Error as e:
            raise Exception(f"Autentificare eșuată! PIN greșit pentru token-ul ales? Detalii: {e}")

        priv_keys = self.session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), 
            (PyKCS11.CKA_ID, list(target_cka_id))
        ])
        if not priv_keys:
            self.logout()
            raise Exception("Cheia privată nu a putut fi găsită. Posibil ca PIN-ul să fie pentru alt certificat.")
        
        self.priv_key = priv_keys[0]

        certs = self.session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE), 
            (PyKCS11.CKA_ID, list(target_cka_id))
        ])
        
        if certs:
            self.cert_der = bytes(self.session.getAttributeValue(certs[0], [PyKCS11.CKA_VALUE])[0])
        else:
            self.logout()
            raise Exception("Certificatul fizic nu a putut fi extras.")

    def certificate(self):
        return self.cert_der, self.cert_der

    def sign(self, *args):
        try:
            if len(args) == 3:
                keyid, data, algo = args
            else:
                data, algo = args[0], args[1]

            if algo == 'sha256':
                mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
            else:
                raise Exception(f"Algoritm nesuportat: {algo}")
                
            sig = self.session.sign(self.priv_key, data, mech)
            return bytes(sig)
        except Exception as e:
            logging.error("Eroare la semnarea hardware", exc_info=True)
            raise e

    def logout(self):
        try:
            self.session.logout()
            self.session.closeSession()
        except: pass


@dataclass
class SigningTask:
    pdf_path: str
    page_index: int
    box: Tuple[int, int, int, int]


class FileListWidget(tk.Frame):
    def __init__(self, parent, app, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.app = app
        
        self.canvas = tk.Canvas(self, bg="#1a1a2e", bd=0, highlightthickness=0, height=220)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg="#1a1a2e")
        
        self.scrollable_frame.bind("<Configure>", self._on_frame_configure)
        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.bind('<Configure>', self._on_canvas_configure)

        # mousewheel scrolling
        self.canvas.bind("<Button-4>", lambda e: self.canvas.yview_scroll(-1, "units"))
        self.canvas.bind("<Button-5>", lambda e: self.canvas.yview_scroll(1, "units"))
        self.canvas.bind("<MouseWheel>", lambda e: self.canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
        
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.items = []
        self.selected_idx = -1

    def _on_frame_configure(self, event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self.canvas.itemconfig(self.canvas_window, width=event.width)

    def _update_scroll(self):
        self.scrollable_frame.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def insert(self, idx, text):
        if idx == "end":
            idx = len(self.items)
            
        f = tk.Frame(self.scrollable_frame, bg="#1a1a2e")
        
        btn = tk.Button(f, text="🗑", bg="#1a1a2e", fg="#e94560", activebackground="#e94560", activeforeground="white", bd=0, cursor="hand2")
        btn.pack(side="right", padx=5)

        lbl = tk.Label(f, text=text, bg="#1a1a2e", fg="#eaeaea", anchor="w", cursor="hand2")
        lbl.pack(side="left", fill="x", expand=True, padx=5, pady=2)

        # mousewheel on each item row too
        for widget in (f, lbl, btn):
            widget.bind("<Button-4>", lambda e: self.canvas.yview_scroll(-1, "units"))
            widget.bind("<Button-5>", lambda e: self.canvas.yview_scroll(1, "units"))
            widget.bind("<MouseWheel>", lambda e: self.canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
        
        self.items.insert(idx, {"frame": f, "label": lbl, "button": btn})
        self._repack()
        self.after(10, self._update_scroll)

    def _repack(self):
        for i, item in enumerate(self.items):
            item["frame"].pack_forget()
            item["frame"].pack(fill="x", pady=1)
            
            item["button"].config(command=lambda idx=i: self.app._delete_pdf(idx))
            
            def make_on_click(idx):
                def on_click(e):
                    self.select_idx(idx)
                    self.app._on_list_select(None)
                return on_click
                
            on_click_handler = make_on_click(i)
            item["label"].bind("<Button-1>", on_click_handler)
            item["frame"].bind("<Button-1>", on_click_handler)
            
            if i == self.selected_idx:
                item["frame"].config(bg="#e94560")
                item["label"].config(bg="#e94560")
            else:
                item["frame"].config(bg="#1a1a2e")
                item["label"].config(bg="#1a1a2e")

        self.after(10, self._update_scroll)

    def select_idx(self, idx):
        self.selected_idx = idx
        self._repack()

    def delete(self, idx, end=None):
        if idx == 0 and end == "end":
            for item in self.items:
                item["frame"].destroy()
            self.items.clear()
            self.selected_idx = -1
        else:
            if idx < len(self.items):
                self.items[idx]["frame"].destroy()
                self.items.pop(idx)
                if self.selected_idx == idx:
                    self.selected_idx = -1
                elif self.selected_idx > idx:
                    self.selected_idx -= 1
                self._repack()

    def curselection(self):
        return [self.selected_idx] if self.selected_idx != -1 else []
        
    def drop_target_register(self, dnd_type):
        self.canvas.drop_target_register(dnd_type)
        
    def dnd_bind(self, sequence, func):
        self.canvas.dnd_bind(sequence, func)


class PDFSignerApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("Semnătură Digitală PDF Pro")
        self.geometry("1300x850")
        self.configure(bg="#1a1a2e")

        self.pdf_paths, self.tasks = [], []
        self.current_idx = -1
        self.current_page = 0
        self.total_pages = 0
        
        self.pin_var = tk.StringVar()
        self.dll_combo_var = tk.StringVar(value=DEFAULT_DLL)
        self.progress_val = tk.DoubleVar(value=0.0)
        self.cert_mapping = {}
        
        self.settings = self._load_settings()
        
        self._current_photoimg = None
        self._page_pdf_size = (595, 842)
        self._img_offset, self._img_scale = (0, 0), 1.0

        self._build_ui()
        self._style_widgets()
        logging.info("Aplicația UI a pornit cu succes.")

    def _load_settings(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    return {**DEFAULT_SETTINGS, **json.load(f)}
            except Exception as e:
                logging.error(f"Eroare la citirea JSON: {e}")
        return DEFAULT_SETTINGS.copy()

    def _save_settings(self, new_settings):
        self.settings = new_settings
        try:
            with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=4)
        except Exception as e:
            logging.error(f"Eroare la salvarea JSON: {e}")

    def _get_active_dll_path(self):
        """Preia calea DLL-ului fie din dicționarul de presetări, fie pe cea introdusă manual."""
        user_val = self.dll_combo_var.get()
        return DLL_PRESETS.get(user_val, user_val)

    def _browse_dll(self):
        """Permite utilizatorului să caute un fișier driver manual în calculator"""
        if IS_WINDOWS:
            filetypes = [("Fișiere DLL", "*.dll"), ("Toate fișierele", "*.*")]
        else:
            filetypes = [("PKCS#11 Driver Linux", "*.so *.so.*"), ("Toate fișierele", "*.*")]
        file = filedialog.askopenfilename(filetypes=filetypes)
        if file:
            self.dll_combo_var.set(file)

    def _build_ui(self):
        top = tk.Frame(self, bg="#0f3460", height=60)
        top.pack(fill="x")
        tk.Label(top, text="✦ SEMNĂTURĂ DIGITALĂ PDF PRO", font=("Segoe UI", 16, "bold"), bg="#0f3460", fg="#eaeaea").pack(side="left", padx=20)

        def open_support_link():
            import webbrowser
            webbrowser.open("https://buymeacoffee.com/ionutanton")

        btn_support = tk.Button(top, text="☕ Susține proiectul", command=open_support_link, bg="#e94560", fg="white", font=("Segoe UI", 10, "bold"), bd=0, padx=10, pady=5, cursor="hand2")
        btn_support.pack(side="right", padx=20)

        container = tk.Frame(self, bg="#1a1a2e")
        container.pack(fill="both", expand=True)

        self.sidebar = tk.Frame(container, bg="#16213e", width=350)
        self.sidebar.pack(side="left", fill="y", padx=10, pady=10)
        self.sidebar.pack_propagate(False)

        tk.Label(self.sidebar, text="① DOCUMENTE PDF", font=("Segoe UI", 10, "bold"), bg="#16213e", fg="#e94560").pack(anchor="w", padx=15, pady=(10,0))
        f_btns = tk.Frame(self.sidebar, bg="#16213e")
        f_btns.pack(fill="x", padx=15, pady=5)
        tk.Button(f_btns, text="＋ ADAUGĂ", command=self._add_pdfs, bg="#e94560", fg="#eaeaea", bd=0).pack(side="left", expand=True, fill="x", padx=(0,2))
        tk.Button(f_btns, text="✕ GOLEȘTE", command=self._clear_all, bg="#0f3460", fg="#eaeaea", bd=0).pack(side="left", expand=True, fill="x")
        
        self.listb = FileListWidget(self.sidebar, self, bg="#1a1a2e")
        self.listb.pack(fill="x", padx=15, pady=5)
        
        try:
            self.listb.drop_target_register(DND_FILES)
            self.listb.dnd_bind('<<Drop>>', self._on_drop)
            self.sidebar.drop_target_register(DND_FILES)
            self.sidebar.dnd_bind('<<Drop>>', self._on_drop)
            self.drop_target_register(DND_FILES)
            self.dnd_bind('<<Drop>>', self._on_drop)
        except Exception as e:
            logging.error(f"Eroare la activarea drag and drop: {e}")

        tk.Button(self.sidebar, text="⚙ SETĂRI ASPECT SEMNĂTURĂ", command=self._open_settings_dialog, bg="#0f3460", fg="#4ade80", bd=0, pady=8, font=("Segoe UI", 9, "bold")).pack(fill="x", padx=15, pady=(10, 10))

        tk.Label(self.sidebar, text="② CONECTARE TOKEN USB", font=("Segoe UI", 10, "bold"), bg="#16213e", fg="#e94560").pack(anchor="w", padx=15, pady=(10,0))
        
        tk.Label(self.sidebar, text="Furnizor / Driver:" if IS_WINDOWS else "Furnizor / Driver (.so):", font=("Segoe UI", 8), bg="#16213e", fg="#8892a4").pack(anchor="w", padx=15, pady=(5,0))
        
        f_dll = tk.Frame(self.sidebar, bg="#16213e")
        f_dll.pack(fill="x", padx=15, pady=(0, 5))
        
        # OptionMenu (inlocuieste ttk.Combobox care cauzeaza segfault pe Ubuntu)
        self.dll_combo = tk.OptionMenu(f_dll, self.dll_combo_var, *list(DLL_PRESETS.keys()))
        self.dll_combo.config(bg="#1a1a2e", fg="#eaeaea", activebackground="#0f3460",
                              activeforeground="#eaeaea", highlightthickness=0, bd=0, anchor="w")
        self.dll_combo["menu"].config(bg="#1a1a2e", fg="#eaeaea")
        self.dll_combo.pack(side="left", fill="x", expand=True, padx=(0, 5))
        tk.Button(f_dll, text="📂", command=self._browse_dll, bg="#0f3460", fg="#eaeaea", bd=0, width=3, cursor="hand2").pack(side="right")

        f_action = tk.Frame(self.sidebar, bg="#16213e")
        f_action.pack(fill="x", padx=15, pady=(5,10))
        tk.Button(f_action, text="🔍 CITEȘTE CERTIFICATE (FĂRĂ PIN)", command=self._list_token_certs, bg="#0f3460", fg="#eaeaea", font=("Segoe UI", 8, "bold"), bd=0, pady=5, cursor="hand2").pack(fill="x")

        tk.Label(self.sidebar, text="Certificat Găsit:", font=("Segoe UI", 8, "bold"), bg="#16213e", fg="#eaeaea").pack(anchor="w", padx=15)
        self.cert_combo_var = tk.StringVar(value="")
        self.cert_combo = tk.OptionMenu(self.sidebar, self.cert_combo_var, "")
        self.cert_combo.config(bg="#1a1a2e", fg="#eaeaea", activebackground="#0f3460",
                               activeforeground="#eaeaea", highlightthickness=0, bd=0, anchor="w")
        self.cert_combo["menu"].config(bg="#1a1a2e", fg="#eaeaea")
        self.cert_combo.pack(fill="x", padx=15, pady=(0,10))

        tk.Label(self.sidebar, text="PIN Token:", font=("Segoe UI", 9, "bold"), bg="#16213e", fg="#eaeaea").pack(anchor="w", padx=15)
        self.pin_entry = tk.Entry(self.sidebar, textvariable=self.pin_var, show="*", bg="#1a1a2e", fg="#4ade80", bd=0, highlightthickness=1, font=("Segoe UI", 12))
        self.pin_entry.pack(fill="x", padx=15, pady=5)

        tk.Label(self.sidebar, text="Progress bar:", font=("Segoe UI", 9, "bold"), bg="#16213e", fg="#eaeaea").pack(anchor="w", padx=15)
        self.p_bar = ttk.Progressbar(self.sidebar, variable=self.progress_val, maximum=100)
        self.p_bar.pack(fill="x", padx=15, pady=(2, 20))
        self.btn_sign = tk.Button(self.sidebar, text="⚡ APLICĂ SEMNĂTURĂ BATCH", command=self._start_batch, font=("Segoe UI", 10, "bold"), bg="#e94560", fg="#eaeaea", bd=0, pady=15, cursor="hand2")
        self.btn_sign.pack(fill="x", padx=15)

        self.c_area = tk.Frame(container, bg="#1a1a2e")
        self.c_area.pack(side="left", fill="both", expand=True, padx=(0,10), pady=10)

        self.page_frame = tk.Frame(self.c_area, bg="#1a1a2e")
        self.page_frame.pack(fill="x", pady=(0, 5))
        
        tk.Button(self.page_frame, text="⏮ Prima", command=self._page_first, bg="#0f3460", fg="#eaeaea", bd=0, padx=5).pack(side="left", padx=2)
        tk.Button(self.page_frame, text="◀ Ant.", command=self._page_prev, bg="#0f3460", fg="#eaeaea", bd=0, padx=5).pack(side="left", padx=2)
        
        self.page_entry_var = tk.StringVar(value="1")
        self.page_entry = tk.Entry(self.page_frame, textvariable=self.page_entry_var, width=5, justify="center")
        self.page_entry.pack(side="left", padx=5)
        self.page_entry.bind("<Return>", self._page_goto)
        
        self.page_label = tk.Label(self.page_frame, text="/ 1", bg="#1a1a2e", fg="#eaeaea")
        self.page_label.pack(side="left", padx=(0, 5))

        tk.Button(self.page_frame, text="Urm. ▶", command=self._page_next, bg="#0f3460", fg="#eaeaea", bd=0, padx=5).pack(side="left", padx=2)
        tk.Button(self.page_frame, text="Ultima ⏭", command=self._page_last, bg="#0f3460", fg="#eaeaea", bd=0, padx=5).pack(side="left", padx=2)

        self.canvas = tk.Canvas(self.c_area, bg="#2d2d2d", bd=0, highlightthickness=0, cursor="crosshair")
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<ButtonPress-1>", self._on_mouse_press)
        self.canvas.bind("<B1-Motion>", self._on_mouse_drag)
        self.canvas.bind("<ButtonRelease-1>", self._on_mouse_release)
        
        self.canvas.bind("<MouseWheel>", self._on_mouse_wheel)
        self.canvas.bind("<Button-4>", self._on_mouse_wheel)
        self.canvas.bind("<Button-5>", self._on_mouse_wheel)

    def _on_mouse_wheel(self, event):
        if self.current_idx != -1:
            if event.num == 4 or event.delta > 0:
                self._page_prev()
            elif event.num == 5 or event.delta < 0:
                self._page_next()

    def _list_token_certs(self):
        dll_path = self._get_active_dll_path()
        self.cert_combo_var.set("Caut pe porturile USB...")
        
        def fetch():
            try:
                certs = HardwareTokenHSM.list_all_certificates(dll_path)
                self.after(0, lambda: self._update_cert_dropdown(certs))
            except Exception as e:
                self.after(0, lambda err=str(e): messagebox.showerror("Eroare Driver/Hardware", f"Verifică dacă driver-ul DLL/SO e corect și token-ul e în PC.\n\nDetalii: {err}"))
                self.after(0, lambda: self.cert_combo_var.set(""))

        threading.Thread(target=fetch, daemon=True).start()

    def _update_cert_dropdown(self, certs):
        self.cert_mapping.clear()
        menu = self.cert_combo["menu"]
        menu.delete(0, "end")
        if not certs:
            self.cert_combo_var.set("")
            messagebox.showwarning("Atenție", "Nu a fost găsit niciun certificat pe token-urile conectate.")
            return

        for c in certs:
            hex_id = bytes(c['cka_id']).hex()[:6].upper()
            display_name = f"{c['cn']} ({c['token_label']}) [{hex_id}]"
            self.cert_mapping[display_name] = {'slot': c['slot'], 'cka_id': c['cka_id']}

        for name in self.cert_mapping.keys():
            menu.add_command(label=name, command=lambda v=name: self.cert_combo_var.set(v))
        self.cert_combo_var.set(list(self.cert_mapping.keys())[0])

    # --- GUI SETĂRI ASPECT ---
    def _open_settings_dialog(self):
        diag = tk.Toplevel(self)
        diag.title("Personalizare Semnătură")
        diag.geometry("900x550")
        diag.configure(bg="#1a1a2e")
        diag.grab_set()
        
        diag._preview_logo = None

        v_contact = tk.StringVar(value=self.settings.get("contact", ""))
        v_location = tk.StringVar(value=self.settings.get("location", ""))
        v_reason = tk.StringVar(value=self.settings.get("reason", ""))
        v_border = tk.IntVar(value=self.settings.get("border", 1))
        v_bg = tk.StringVar(value=self.settings.get("bg_color", "#ffffff"))
        v_out = tk.StringVar(value=self.settings.get("outline_color", "#000000"))
        
        v_d_cn = tk.BooleanVar(value=self.settings.get("display_cn", True))
        v_d_date = tk.BooleanVar(value=self.settings.get("display_date", True))
        v_d_reason = tk.BooleanVar(value=self.settings.get("display_reason", True))
        v_d_loc = tk.BooleanVar(value=self.settings.get("display_location", False))
        v_d_cont = tk.BooleanVar(value=self.settings.get("display_contact", False))

        v_fontsize = tk.IntVar(value=self.settings.get("fontsize", 8))
        v_textalign = tk.StringVar(value=self.settings.get("textalign", "left"))
        v_linespacing = tk.DoubleVar(value=self.settings.get("linespacing", 1.2))
        
        v_lbl_cn = tk.StringVar(value=self.settings.get("lbl_cn", ""))
        v_lbl_date = tk.StringVar(value=self.settings.get("lbl_date", ""))
        v_lbl_reason = tk.StringVar(value=self.settings.get("lbl_reason", "Motiv:"))
        v_lbl_loc = tk.StringVar(value=self.settings.get("lbl_loc", ""))
        v_lbl_contact = tk.StringVar(value=self.settings.get("lbl_contact", ""))

        v_use_img = tk.BooleanVar(value=self.settings.get("use_image", False))
        v_img_path = tk.StringVar(value=self.settings.get("image_path", ""))

        def choose_color(var):
            color = colorchooser.askcolor(initialcolor=var.get(), title="Alege Culoare")
            if color[1]: var.set(color[1])
            update_preview()

        def save():
            new_s = {
                "contact": v_contact.get(), "location": v_location.get(), "reason": v_reason.get(),
                "border": v_border.get(), "bg_color": v_bg.get(), "outline_color": v_out.get(),
                "display_cn": v_d_cn.get(), "display_date": v_d_date.get(), 
                "display_reason": v_d_reason.get(), "display_location": v_d_loc.get(), "display_contact": v_d_cont.get(),
                "fontsize": v_fontsize.get(), "textalign": v_textalign.get(), "linespacing": v_linespacing.get(),
                "lbl_cn": v_lbl_cn.get(), "lbl_date": v_lbl_date.get(), "lbl_reason": v_lbl_reason.get(),
                "lbl_loc": v_lbl_loc.get(), "lbl_contact": v_lbl_contact.get(),
                "use_image": v_use_img.get(), "image_path": v_img_path.get()
            }
            self._save_settings(new_s)
            diag.destroy()

        left_f = tk.Frame(diag, bg="#1a1a2e")
        left_f.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        
        notebook = ttk.Notebook(left_f)
        notebook.pack(fill="both", expand=True)

        t1 = tk.Frame(notebook, bg="#1a1a2e", padx=15, pady=15)
        notebook.add(t1, text="Date & Câmpuri")
        tk.Label(t1, text="Valorile Metadata:", font=("Segoe UI", 10, "bold"), bg="#1a1a2e", fg="#e94560").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0,5))
        tk.Label(t1, text="Motiv (Reason):", bg="#1a1a2e", fg="#eaeaea").grid(row=1, column=0, sticky="w")
        tk.Entry(t1, textvariable=v_reason, width=30).grid(row=1, column=1, pady=2)
        tk.Label(t1, text="Locație (Location):", bg="#1a1a2e", fg="#eaeaea").grid(row=2, column=0, sticky="w")
        tk.Entry(t1, textvariable=v_location, width=30).grid(row=2, column=1, pady=2)
        tk.Label(t1, text="Contact:", bg="#1a1a2e", fg="#eaeaea").grid(row=3, column=0, sticky="w")
        tk.Entry(t1, textvariable=v_contact, width=30).grid(row=3, column=1, pady=2)

        tk.Label(t1, text="Elemente vizibile pe PDF:", font=("Segoe UI", 10, "bold"), bg="#1a1a2e", fg="#e94560").grid(row=4, column=0, columnspan=2, sticky="w", pady=(15,5))
        tk.Checkbutton(t1, text="Numele (CN)", variable=v_d_cn, bg="#1a1a2e", fg="#4ade80", selectcolor="#0f3460").grid(row=5, column=0, sticky="w")
        tk.Checkbutton(t1, text="Data Semnării", variable=v_d_date, bg="#1a1a2e", fg="#4ade80", selectcolor="#0f3460").grid(row=5, column=1, sticky="w")
        tk.Checkbutton(t1, text="Motivul", variable=v_d_reason, bg="#1a1a2e", fg="#4ade80", selectcolor="#0f3460").grid(row=6, column=0, sticky="w")
        tk.Checkbutton(t1, text="Locația", variable=v_d_loc, bg="#1a1a2e", fg="#4ade80", selectcolor="#0f3460").grid(row=6, column=1, sticky="w")
        tk.Checkbutton(t1, text="Contactul", variable=v_d_cont, bg="#1a1a2e", fg="#4ade80", selectcolor="#0f3460").grid(row=7, column=0, sticky="w")

        t2 = tk.Frame(notebook, bg="#1a1a2e", padx=15, pady=15)
        notebook.add(t2, text="Aspect Vizual")
        tk.Label(t2, text="Culori și Contur:", font=("Segoe UI", 10, "bold"), bg="#1a1a2e", fg="#e94560").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0,5))
        tk.Label(t2, text="Grosime chenar:", bg="#1a1a2e", fg="#eaeaea").grid(row=1, column=0, sticky="w")
        tk.Spinbox(t2, from_=0, to=5, textvariable=v_border, width=10).grid(row=1, column=1, sticky="w", pady=2)
        tk.Button(t2, text="🎨 Fundal", command=lambda: choose_color(v_bg), bg="#0f3460", fg="white", bd=0, width=15).grid(row=2, column=0, pady=5, sticky="w")
        tk.Button(t2, text="🎨 Text/Contur", command=lambda: choose_color(v_out), bg="#0f3460", fg="white", bd=0, width=15).grid(row=2, column=1, pady=5, sticky="w")

        tk.Label(t2, text="Formatare Text:", font=("Segoe UI", 10, "bold"), bg="#1a1a2e", fg="#e94560").grid(row=3, column=0, columnspan=2, sticky="w", pady=(15,5))
        tk.Label(t2, text="Mărime Text (Font):", bg="#1a1a2e", fg="#eaeaea").grid(row=4, column=0, sticky="w")
        tk.Spinbox(t2, from_=4, to=36, textvariable=v_fontsize, width=10).grid(row=4, column=1, sticky="w", pady=2)
        tk.Label(t2, text="Aliniere Text:", bg="#1a1a2e", fg="#eaeaea").grid(row=5, column=0, sticky="w")
        cb_align = tk.OptionMenu(t2, v_textalign, "left", "center", "right")
        cb_align.config(bg="#1a1a2e", fg="#eaeaea", activebackground="#0f3460",
                        activeforeground="#eaeaea", highlightthickness=0, bd=0)
        cb_align["menu"].config(bg="#1a1a2e", fg="#eaeaea")
        cb_align.grid(row=5, column=1, sticky="w", pady=2)

        t3 = tk.Frame(notebook, bg="#1a1a2e", padx=15, pady=15)
        notebook.add(t3, text="Etichete (Prefixe)")
        tk.Label(t3, text="Lasă gol pentru a ascunde prefixul:", font=("Segoe UI", 9, "bold"), bg="#1a1a2e", fg="#e94560").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0,10))
        tk.Label(t3, text="Prefix Nume (CN):", bg="#1a1a2e", fg="#eaeaea").grid(row=1, column=0, sticky="w")
        tk.Entry(t3, textvariable=v_lbl_cn, width=35).grid(row=1, column=1, pady=2)
        tk.Label(t3, text="Prefix Dată:", bg="#1a1a2e", fg="#eaeaea").grid(row=2, column=0, sticky="w")
        tk.Entry(t3, textvariable=v_lbl_date, width=35).grid(row=2, column=1, pady=2)
        tk.Label(t3, text="Prefix Motiv:", bg="#1a1a2e", fg="#eaeaea").grid(row=3, column=0, sticky="w")
        tk.Entry(t3, textvariable=v_lbl_reason, width=35).grid(row=3, column=1, pady=2)
        tk.Label(t3, text="Prefix Locație:", bg="#1a1a2e", fg="#eaeaea").grid(row=4, column=0, sticky="w")
        tk.Entry(t3, textvariable=v_lbl_loc, width=35).grid(row=4, column=1, pady=2)

        t4 = tk.Frame(notebook, bg="#1a1a2e", padx=15, pady=15)
        notebook.add(t4, text="Imagine / Logo")
        tk.Checkbutton(t4, text="Afișează o imagine în stânga (ex: Logo / Ștampilă)", variable=v_use_img, bg="#1a1a2e", fg="#4ade80", selectcolor="#0f3460").pack(anchor="w", pady=(0, 10))
        tk.Label(t4, text="Calea către imagine (PNG / JPG):", bg="#1a1a2e", fg="#eaeaea").pack(anchor="w")
        f_img = tk.Frame(t4, bg="#1a1a2e")
        f_img.pack(fill="x", pady=5)
        tk.Entry(f_img, textvariable=v_img_path).pack(side="left", fill="x", expand=True, padx=(0, 5))
        def browse_img():
            p = filedialog.askopenfilename(filetypes=[("Imagini", "*.png *.jpg *.jpeg")])
            if p: v_img_path.set(p)
            update_preview()
        tk.Button(f_img, text="📂 Alege...", command=browse_img, bg="#0f3460", fg="white", bd=0, padx=10).pack(side="right")

        # PREVIEW
        right_f = tk.Frame(diag, bg="#16213e", padx=20, pady=20, width=350)
        right_f.pack(side="right", fill="y")
        tk.Label(right_f, text="PREVIZUALIZARE LIVE", font=("Segoe UI", 12, "bold"), bg="#16213e", fg="#eaeaea").pack(pady=(0,10))
        cvs_preview = tk.Canvas(right_f, width=350, height=200, bg="#dcdcdc", bd=0, highlightthickness=0)
        cvs_preview.pack(pady=10)
        tk.Button(right_f, text="💾 SALVEAZĂ SETĂRI", command=save, bg="#e94560", fg="white", font=("Segoe UI", 10, "bold"), bd=0, pady=15).pack(side="bottom", fill="x")

        def update_preview(*args):
            cvs_preview.delete("all")
            bg_c = v_bg.get()
            out_c = v_out.get()
            bw = v_border.get()
            f_size = v_fontsize.get()
            
            pad_out = 15
            box_w = 320
            box_h = 170
            cvs_preview.create_rectangle(pad_out, pad_out, pad_out + box_w, pad_out + box_h, fill=bg_c, outline=out_c, width=bw)
            
            img_offset_x = 0
            if v_use_img.get() and os.path.exists(v_img_path.get()):
                try:
                    pil_img = Image.open(v_img_path.get())
                    ph = box_h - 10
                    pw = int(ph * (pil_img.width / pil_img.height))
                    pil_img = pil_img.resize((pw, ph), Image.LANCZOS)
                    diag._preview_logo = ImageTk.PhotoImage(pil_img)
                    cvs_preview.create_image(pad_out + 5, pad_out + 5, anchor="nw", image=diag._preview_logo)
                    img_offset_x = pw + 10 
                except: pass

            def cln(lbl):
                return lbl.strip() + " " if lbl.strip() else ""

            lines = []
            if v_d_cn.get(): lines.append(cln(v_lbl_cn.get()) + "NUME PRENUME TITULAR")
            if v_d_date.get(): lines.append(cln(v_lbl_date.get()) + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            if v_d_reason.get(): lines.append(cln(v_lbl_reason.get()) + v_reason.get())
            if v_d_loc.get(): lines.append(cln(v_lbl_loc.get()) + v_location.get())
            if v_d_cont.get(): lines.append(cln(v_lbl_contact.get()) + v_contact.get())
            
            text_str = "\n".join(lines)
            
            pad_left = pad_out + 5 + img_offset_x
            pad_right = pad_out + box_w - 5
            
            anchor_p = "nw"
            x_pos = pad_left
            if v_textalign.get() == "center":
                anchor_p = "n"
                x_pos = pad_left + (pad_right - pad_left) / 2
            elif v_textalign.get() == "right":
                anchor_p = "ne"
                x_pos = pad_right

            safe_size = min(max(f_size, 6), 24)
            cvs_preview.create_text(x_pos, pad_out + 10, anchor=anchor_p, text=text_str, fill=out_c, font=("Arial", safe_size), justify=v_textalign.get())

        for var in (v_reason, v_location, v_contact, v_border, v_bg, v_out, v_d_cn, v_d_date, v_d_reason, v_d_loc, v_d_cont, v_fontsize, v_textalign, v_lbl_cn, v_lbl_date, v_lbl_reason, v_lbl_loc, v_lbl_contact, v_use_img, v_img_path):
            var.trace_add("write", update_preview)
            
        update_preview()

    # --- EXECUȚIE SEMNARE ---
    def _execute_sign(self, task: SigningTask, hsm: HardwareTokenHSM):
        input_path = os.path.normpath(task.pdf_path)
        output_dir = os.path.join(os.path.dirname(input_path), "Semnate")
        if not os.path.exists(output_dir): 
            os.makedirs(output_dir)
        output_path = os.path.join(output_dir, f"{Path(input_path).stem}_semnat.pdf")

        x1, y1, x2, y2 = task.box
        w = abs(x2 - x1)
        h = abs(y2 - y1)

        raw_date = datetime.datetime.now(datetime.timezone.utc).strftime("D:%Y%m%d%H%M%S+00'00'")
        viz_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cert_obj = x509.load_der_x509_certificate(hsm.cert_der, default_backend())
        try:
            cn_name = cert_obj.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except:
            cn_name = "Semnătură Necunoscută"

        def cln(lbl):
            return lbl.strip() + " " if lbl.strip() else ""

        lines = []
        if self.settings["display_cn"]: lines.append(cln(self.settings["lbl_cn"]) + cn_name)
        if self.settings["display_date"]: lines.append(cln(self.settings["lbl_date"]) + viz_date)
        if self.settings["display_reason"]: lines.append(cln(self.settings["lbl_reason"]) + self.settings["reason"])
        if self.settings["display_location"]: lines.append(cln(self.settings["lbl_loc"]) + self.settings["location"])
        if self.settings["display_contact"]: lines.append(cln(self.settings["lbl_contact"]) + self.settings["contact"])
        
        text_str = "\n".join(lines)

        bg_r, bg_g, bg_b = hex_to_rgb(self.settings["bg_color"])
        out_r, out_g, out_b = hex_to_rgb(self.settings["outline_color"])
        fs = self.settings["fontsize"]
        align = self.settings["textalign"]

        sig_manual = [
            ['fill_colour', bg_r, bg_g, bg_b],
            ['rect_fill', 0, 0, w, h],
            ['stroke_colour', out_r, out_g, out_b],
            ['border', self.settings["border"]],
        ]

        img_offset_w = 0
        manual_images = {}

        if self.settings.get("use_image") and os.path.exists(self.settings.get("image_path")):
            try:
                with Image.open(self.settings["image_path"]) as tmp_img:
                    iw, ih = tmp_img.size
                
                pad = 4
                avail_h = h - (pad * 2)
                avail_w = int(avail_h * (iw / ih))
                
                sig_manual.append(['image', 'sig0', pad, pad, avail_w, avail_h])
                manual_images['sig0'] = self.settings["image_path"]
                img_offset_w = avail_w + pad
            except Exception as e:
                logging.warning(f"Nu s-a putut procesa imaginea: {e}")

        sig_manual.extend([
            ['fill_colour', out_r, out_g, out_b],
            ['font', 'default', fs],
        ])

        text_x = 2 + img_offset_w
        text_y = 2
        text_w = w - text_x - 2
        text_h = h - 4

        sig_manual.append(['text_box', text_str, 'default', text_x, text_y, text_w, text_h, fs, True, align, 'top'])

        dct = {
            "aligned": 0,
            "sigflags": 3,
            "sigflagsft": 132,
            "sigpage": task.page_index,
            "auto_sigfield": True,
            "signaturebox": (x1, y1, x2, y2),
            "signform": False,
            "contact": self.settings["contact"],
            "location": self.settings["location"],
            "signingdate": raw_date,   
            "reason": self.settings["reason"],
            "signature_manual": sig_manual
        }
        
        if manual_images:
            dct["manual_images"] = manual_images

        try:
            doc = fitz.open(input_path)
            datau = doc.tobytes()
            doc.close()
        except:
            with open(input_path, 'rb') as f:
                datau = f.read()

        datas = cms.sign(datau, dct, None, cert_obj, (), 'sha256', hsm=hsm)

        with open(output_path, 'wb') as f:
            f.write(datau)
            f.write(datas)

    def _run_batch(self, pin, dll_path, target_slot, target_cka_id):
        total = len(self.tasks)
        hsm = None
        try:
            hsm = HardwareTokenHSM(dll_path, pin, target_slot, target_cka_id)
            
            errors = []
            for i, t in enumerate(self.tasks):
                try:
                    self._execute_sign(t, hsm)
                    self.after(0, lambda p=t.pdf_path: self._update_ui_list(p, "✓"))
                except Exception as e:
                    self.after(0, lambda p=t.pdf_path: self._update_ui_list(p, "✗"))
                    logging.error(f"Eroare fișier: {e}")
                    errors.append(f"{os.path.basename(t.pdf_path)}: {str(e)}")
                
                self.after(0, lambda p=((i+1)/total)*100: self.progress_val.set(p))
                
            if errors:
                err_msg = "Au apărut erori la semnarea următoarelor documente:\n\n" + "\n".join(errors)
                self.after(0, lambda msg=err_msg: messagebox.showwarning("Avertisment / Erori", msg))
            else:
                self.after(0, lambda: messagebox.showinfo("Gata", "Toate documentele au fost semnate cu succes!"))
            
        except Exception as e:
            self.after(0, lambda err=str(e): messagebox.showerror("Eroare Hardware", err))
        finally:
            if hsm: 
                hsm.logout()
            self.after(0, lambda: self.btn_sign.config(state="normal"))

    def _start_batch(self):
        if not self.tasks:
            messagebox.showwarning("Incomplet", "Adaugă PDF-uri și desenează chenarul de semnătură.")
            return
        
        selected_cert_name = self.cert_combo_var.get()
        if not selected_cert_name or not hasattr(self, 'cert_mapping') or selected_cert_name not in self.cert_mapping:
            messagebox.showwarning("Incomplet", "Te rog apasă pe CITEȘTE CERTIFICATE și alege cu ce vrei să semnezi.")
            return
            
        pin = self.pin_var.get()
        if not pin:
            messagebox.showwarning("Incomplet", "Introdu PIN-ul pentru certificatul selectat.")
            return

        target_cka_id = self.cert_mapping[selected_cert_name]['cka_id']
        target_slot = self.cert_mapping[selected_cert_name]['slot']
        dll_path = self._get_active_dll_path()
            
        self.btn_sign.config(state="disabled")
        threading.Thread(target=self._run_batch, args=(pin, dll_path, target_slot, target_cka_id), daemon=True).start()

    def _update_page_controls(self):
        self.page_entry_var.set(str(self.current_page + 1))
        self.page_label.config(text=f"/ {self.total_pages}")

    def _page_first(self):
        if self.current_idx != -1: self._load_pdf_preview(self.current_idx, 0)

    def _page_prev(self):
        if self.current_idx != -1 and self.current_page > 0: self._load_pdf_preview(self.current_idx, self.current_page - 1)

    def _page_next(self):
        if self.current_idx != -1 and self.current_page < self.total_pages - 1: self._load_pdf_preview(self.current_idx, self.current_page + 1)

    def _page_last(self):
        if self.current_idx != -1: self._load_pdf_preview(self.current_idx, self.total_pages - 1)

    def _page_goto(self, event=None):
        if self.current_idx != -1:
            try:
                p = int(self.page_entry_var.get()) - 1
                self._load_pdf_preview(self.current_idx, p)
            except ValueError:
                self._update_page_controls()

    def _load_pdf_preview(self, idx, page_num=0):
        self.current_idx = idx
        path = self.pdf_paths[idx]
        try:
            doc = fitz.open(path)
            self.total_pages = doc.page_count
            self.current_page = min(max(0, page_num), self.total_pages - 1)
            page = doc.load_page(self.current_page)
            self._page_pdf_size = (page.rect.width, page.rect.height)
            pix = page.get_pixmap()
            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
            cw, ch = self.canvas.winfo_width(), self.canvas.winfo_height()
            self._img_scale = min(cw/img.width, ch/img.height, 1.0)
            nw, nh = int(img.width * self._img_scale), int(img.height * self._img_scale)
            img = img.resize((nw, nh), Image.LANCZOS)
            self._current_photoimg = ImageTk.PhotoImage(img)
            self._img_offset = ((cw-nw)//2, (ch-nh)//2)
            self.canvas.delete("all")
            self.canvas.create_image(self._img_offset[0], self._img_offset[1], anchor="nw", image=self._current_photoimg)
            doc.close()
            self._update_page_controls()
            
            for t in self.tasks:
                if t.pdf_path == path and t.page_index == self.current_page:
                    ox, oy, sc = self._img_offset[0], self._img_offset[1], self._img_scale
                    pw, ph = self._page_pdf_size
                    x1, y1, x2, y2 = t.box
                    cx1 = x1 * sc + ox
                    cy1 = (ph - y2) * sc + oy
                    cx2 = x2 * sc + ox
                    cy2 = (ph - y1) * sc + oy
                    self.canvas.create_rectangle(cx1, cy1, cx2, cy2, outline="#e94560", width=2, tags="sig_rect")
                    break
        except Exception as e:
            logging.error(f"Eroare _load_pdf_preview: {e}")

    def _delete_pdf(self, idx):
        if idx < 0 or idx >= len(self.pdf_paths): return
        path = self.pdf_paths[idx]
        self.pdf_paths.pop(idx)
        self.tasks = [t for t in self.tasks if t.pdf_path != path]
        
        self.listb.delete(idx)
        
        if not self.pdf_paths:
            self._clear_all()
        else:
            if self.current_idx == idx:
                new_idx = min(idx, len(self.pdf_paths) - 1)
                self.listb.select_idx(new_idx)
                self._load_pdf_preview(new_idx)
            elif self.current_idx > idx:
                self.current_idx -= 1
                self._load_pdf_preview(self.current_idx)

    def _add_pdfs(self):
        files = filedialog.askopenfilenames(filetypes=[("PDF", "*.pdf")])
        for f in files:
            if f not in self.pdf_paths:
                self.pdf_paths.append(f); self.listb.insert("end", os.path.basename(f))
        if self.pdf_paths: self._load_pdf_preview(0)

    def _on_drop(self, event):
        files = self.tk.splitlist(event.data)
        added = False
        for f in files:
            if isinstance(f, bytes):
                try:
                    f = f.decode('utf-8')
                except UnicodeDecodeError:
                    if IS_WINDOWS:
                        f = f.decode('mbcs')
                    else:
                        f = f.decode('latin-1')
            if f.lower().endswith('.pdf'):
                if f not in self.pdf_paths:
                    self.pdf_paths.append(f)
                    self.listb.insert("end", os.path.basename(f))
                    added = True
        if added and self.current_idx == -1:
            self._load_pdf_preview(0)

    def _on_list_select(self, e):
        sel = self.listb.curselection()
        if sel: 
            idx = sel[0]
            path = self.pdf_paths[idx]
            page_num = 0
            for t in self.tasks:
                if t.pdf_path == path:
                    page_num = t.page_index
                    break
            self._load_pdf_preview(idx, page_num)

    def _on_mouse_press(self, e): 
        self._drag_start = (e.x, e.y)
        self.canvas.delete("sig_rect")
        
    def _on_mouse_drag(self, e):
        if getattr(self, '_drag_start', None):
            self.canvas.delete("sig_rect")
            self.canvas.create_rectangle(self._drag_start[0], self._drag_start[1], e.x, e.y, outline="#e94560", width=2, tags="sig_rect")

    def _on_mouse_release(self, e):
        if getattr(self, '_drag_start', None) and self.current_idx != -1:
            ox, oy, sc = self._img_offset[0], self._img_offset[1], self._img_scale
            pw, ph = self._page_pdf_size
            rx1, ry1 = (min(self._drag_start[0], e.x) - ox) / sc, (min(self._drag_start[1], e.y) - oy) / sc
            rx2, ry2 = (max(self._drag_start[0], e.x) - ox) / sc, (max(self._drag_start[1], e.y) - oy) / sc
            box = (int(rx1), int(ph - ry2), int(rx2), int(ph - ry1))
            self._set_task(self.current_idx, box)
            self._drag_start = None

    def _set_task(self, idx, box):
        path = self.pdf_paths[idx]
        for t in self.tasks:
            if t.pdf_path == path: 
                t.box = box
                t.page_index = self.current_page
                return
        self.tasks.append(SigningTask(path, self.current_page, box))

    def _update_ui_list(self, path, char):
        try:
            idx = self.pdf_paths.index(path)
            self.listb.delete(idx)
            self.listb.insert(idx, f"{char} {os.path.basename(path)}")
        except: pass

    def _clear_all(self):
        self.pdf_paths, self.tasks = [], []
        self.listb.delete(0, "end")
        self.canvas.delete("all")
        self.cert_combo_var.set("")
        self.cert_combo["menu"].delete(0, "end")
        self.current_idx = -1
        self.current_page = 0
        self.total_pages = 0
        if hasattr(self, 'page_entry_var'):
            self.page_entry_var.set("1")
            self.page_label.config(text="/ 1")

    def _style_widgets(self):
        s = ttk.Style()
        s.theme_use("default")
        s.configure("TProgressbar", troughcolor="#1a1a2e", background="#e94560", thickness=12)

if __name__ == "__main__":
    app = PDFSignerApp()
    app.mainloop()