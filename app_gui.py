"""
Tkinter GUI for the CSE721 Encryption/Decryption Tool.
Cross-platform (Windows/macOS/Linux) as long as Tkinter is available.
Run: python app_gui.py
"""

import re
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from cryptoSuite.cryptoSuite import CaesarCipher, AffineCipher, PlayfairCipher, HillCipher

def parse_affine(s: str):
    parts = [p for p in s.replace(",", " ").split() if p.strip()]
    if len(parts) != 2:
        raise ValueError("Affine key must have two integers: a b (e.g., 5 8).")
    a, b = int(parts[0]), int(parts[1])
    # a must be invertible mod 26
    try:
        pow(a, -1, 26)
    except ValueError:
        raise ValueError("Affine key invalid: 'a' must satisfy gcd(a, 26)=1 (invertible mod 26).")
    return (a, b)

def parse_hill(s: str):
    nums = list(map(int, re.findall(r"-?\d+", s)))
    if len(nums) != 4:
        raise ValueError("Hill key must contain exactly 4 integers (2x2 matrix), e.g.:\n3 3\n2 5")
    key = [[nums[0], nums[1]], [nums[2], nums[3]]]
    det = (key[0][0]*key[1][1] - key[0][1]*key[1][0]) % 26
    try:
        pow(det, -1, 26)
    except ValueError:
        raise ValueError("Hill key invalid: matrix not invertible mod 26.")
    return key

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CryptoSuite")
        self.geometry("1100x640")
        self.minsize(1000, 600)

        self.cipher_var = tk.StringVar(value="Caesar")
        self.op_var = tk.StringVar(value="Encrypt")

        self._build_ui()
        self._on_mode_change()

        icon_path = os.path.join(os.path.dirname(__file__), "assets/cryptoSuite.png")
        if os.path.exists(icon_path):
            img = tk.PhotoImage(file=icon_path)
            self.iconphoto(True, img)
            self._icon_ref = img 

    def _build_ui(self):
        top = ttk.Frame(self, padding=12)
        top.pack(fill="x")

        members = ttk.Label(
            top,
            text="Developed by: Abdullah Khondoker (ID: 20301065) | A.S.M Mahabub Siddiqui (ID: 20301040)",
            font=("Segoe UI", 10, "italic")
        )
        members.grid(row=0, column=4, sticky="e")
        top.columnconfigure(4, weight=1)

        ttk.Label(top, text="Cipher:").grid(row=0, column=0, sticky="w")
        cipher = ttk.Combobox(top, textvariable=self.cipher_var, values=["Caesar", "Affine", "Playfair", "Hill"], width=12, state="readonly")
        cipher.grid(row=0, column=1, padx=(6, 18), sticky="w")
        cipher.bind("<<ComboboxSelected>>", lambda e: self._on_mode_change())

        ttk.Label(top, text="Operation:").grid(row=0, column=2, sticky="w")
        op = ttk.Combobox(top, textvariable=self.op_var, values=["Encrypt", "Decrypt", "Crack Hill Key (Known Plaintext)"], width=30, state="readonly")
        op.grid(row=0, column=3, padx=(6, 18), sticky="w")
        op.bind("<<ComboboxSelected>>", lambda e: self._on_mode_change())

        self.key_label = ttk.Label(top, text="Key:")
        self.key_label.grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.key_entry = ttk.Entry(top, width=55)
        self.key_entry.grid(row=1, column=1, columnspan=3, sticky="we", pady=(10, 0))

        # Helpful hint
        self.hint = ttk.Label(top, text="", foreground="#444")
        self.hint.grid(row=2, column=0, columnspan=4, sticky="w", pady=(6, 0))

        # Main text areas
        mid = ttk.Frame(self, padding=(12, 6))
        mid.pack(fill="both", expand=True)

        self.input_label = ttk.Label(mid, text="Input:")
        self.input_label.grid(row=0, column=0, sticky="w")

        self.input_text = tk.Text(mid, height=9, wrap="word")
        self.input_text.grid(row=1, column=0, columnspan=3, sticky="nsew", pady=(4, 10))

        self.extra_label = ttk.Label(mid, text="Known Ciphertext (for Hill crack):")
        self.extra_text = tk.Text(mid, height=7, wrap="word")

        self.output_label = ttk.Label(mid, text="Output:")
        self.output_label.grid(row=4, column=0, sticky="w")

        self.output_text = tk.Text(mid, height=10, wrap="word")
        self.output_text.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=(4, 0))

        # Buttons
        btns = ttk.Frame(self, padding=(12, 10))
        btns.pack(fill="x")

        ttk.Button(btns, text="Run", command=self.run).pack(side="left")
        ttk.Button(btns, text="Clear", command=self.clear).pack(side="left", padx=8)

        ttk.Button(btns, text="Load Input...", command=self.load_input).pack(side="right")
        ttk.Button(btns, text="Save Output...", command=self.save_output).pack(side="right", padx=8)

        # Grid weights
        mid.columnconfigure(0, weight=1)
        mid.columnconfigure(1, weight=1)
        mid.columnconfigure(2, weight=1)
        mid.rowconfigure(1, weight=1)
        mid.rowconfigure(5, weight=1)

    def _on_mode_change(self):
        cipher = self.cipher_var.get()
        op = self.op_var.get()

        # default key hints
        if cipher == "Caesar":
            hint = "Caesar key: integer shift (e.g., 5)"
        elif cipher == "Affine":
            hint = "Affine key: a b (e.g., 5 8), with gcd(a,26)=1"
        elif cipher == "Playfair":
            hint = "Playfair key: keyword (letters). J is treated as I."
        else:
            hint = "Hill key (2x2): 4 integers, e.g. 3 3 / 2 5 (matrix must be invertible mod 26)"
        self.hint.config(text=hint)

        if op.startswith("Crack"):
            # Crack is only meaningful for Hill
            self.cipher_var.set("Hill")
            self.key_entry.configure(state="disabled")
            self.key_label.configure(text="Key: (not needed)")
            self.input_label.configure(text="Known Plaintext:")
            self._show_extra_ciphertext(True)
        else:
            self.key_entry.configure(state="normal")
            self.key_label.configure(text="Key:")
            self.input_label.configure(text="Plaintext:" if op == "Encrypt" else "Ciphertext:")
            self._show_extra_ciphertext(False)

    def _show_extra_ciphertext(self, show: bool):
        mid = self.input_text.master
        if show:
            self.extra_label.grid(row=2, column=0, sticky="w")
            self.extra_text.grid(row=3, column=0, columnspan=3, sticky="nsew", pady=(4, 10))
            mid.rowconfigure(3, weight=1)
        else:
            self.extra_label.grid_forget()
            self.extra_text.grid_forget()
            mid.rowconfigure(3, weight=0)

    def clear(self):
        self.input_text.delete("1.0", "end")
        self.output_text.delete("1.0", "end")
        self.extra_text.delete("1.0", "end")

    def load_input(self):
        path = filedialog.askopenfilename(title="Open text file", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", content)

    def save_output(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", title="Save output", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        out = self.output_text.get("1.0", "end-1c")
        with open(path, "w", encoding="utf-8") as f:
            f.write(out)
        messagebox.showinfo("Saved", f"Output saved to:\n{path}")

    def _build_cipher(self, cipher_name: str, key_text: str):
        if cipher_name == "Caesar":
            return CaesarCipher(int(key_text.strip()))
        if cipher_name == "Affine":
            return AffineCipher(parse_affine(key_text))
        if cipher_name == "Playfair":
            key = key_text.strip()
            if not key:
                raise ValueError("Playfair key cannot be empty.")
            return PlayfairCipher(key)
        if cipher_name == "Hill":
            return HillCipher(parse_hill(key_text))
        raise ValueError("Unknown cipher")

    def run(self):
        cipher_name = self.cipher_var.get()
        op = self.op_var.get()

        try:
            if op.startswith("Crack"):
                plain = self.input_text.get("1.0", "end-1c")
                ciph = self.extra_text.get("1.0", "end-1c")
                key = HillCipher().crack_key(plain, ciph)
                if not key:
                    raise ValueError("Could not recover a Hill key from the provided texts.")
                out = "Recovered Hill key (2x2):\n" + "\n".join(" ".join(map(str, row)) for row in key)
            else:
                key_text = self.key_entry.get()
                if not key_text.strip():
                    raise ValueError("Key is required.")
                text = self.input_text.get("1.0", "end-1c")
                cipher = self._build_cipher(cipher_name, key_text)
                out = cipher.encrypt(text) if op == "Encrypt" else cipher.decrypt(text)

            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", out)

        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    try:
        App().mainloop()
    except Exception as e:
        # If Tk cannot initialize (rare), show a helpful message.
        raise
