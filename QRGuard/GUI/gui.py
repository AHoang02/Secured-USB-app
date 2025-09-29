import os
import io
import subprocess
import sys
import tempfile
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, messagebox
from PIL import Image, ImageTk

RUST_BINARY = "./QRguard.exe" if sys.platform == "win32" else "./QRguard"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

class QRGuardApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("QR-Guard GUI")
        self.geometry("600x400")
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        enc = ttk.Frame(nb); nb.add(enc, text="Encrypt")
        self._build_encrypt(enc)

        dec = ttk.Frame(nb); nb.add(dec, text="Decrypt")
        self._build_decrypt(dec)

    def _build_encrypt(self, f):
        ttk.Label(f, text="Input File:").grid(row=0, column=0, sticky="w")
        self.enc_input = ttk.Entry(f, width=50); self.enc_input.grid(row=0, column=1, padx=5)
        ttk.Button(f, text="Browse…", command=self._browse_enc).grid(row=0, column=2)

        ttk.Label(f, text="Validity (min):").grid(row=1, column=0, sticky="w")
        self.enc_minutes = ttk.Spinbox(f, from_=1, to=1440, width=5); self.enc_minutes.set(60)
        self.enc_minutes.grid(row=1, column=1, sticky="w")

        ttk.Button(f, text="Encrypt", command=self._encrypt).grid(row=2, column=1, pady=10)
        self.qr_label = ttk.Label(f); self.qr_label.grid(row=3, column=0, columnspan=3, pady=10)

    def _browse_enc(self):
        p = filedialog.askopenfilename()
        if p:
            self.enc_input.delete(0, tk.END)
            self.enc_input.insert(0, p)

    def _encrypt(self):
        inp = self.enc_input.get(); mins = self.enc_minutes.get()
        if not inp:
            return messagebox.showerror("Error", "Select a file to encrypt.")

        enc_out = inp + ".enc"
        cmd = [RUST_BINARY, "encrypt", "--input", inp, "--output", enc_out, "--minutes", mins]

        try:
            res = subprocess.run(cmd, check=True, capture_output=True, text=True,
                                 creationflags=CREATE_NO_WINDOW)
        except subprocess.CalledProcessError as e:
            return messagebox.showerror("Encryption failed", e.stderr or e.stdout)

        # find QR-PNG path
        qr_path = None
        for line in res.stdout.splitlines():
            if line.startswith("QR-PNG:"):
                qr_path = line.split("QR-PNG:")[1].strip()
                break
        if not qr_path or not os.path.exists(qr_path):
            return messagebox.showerror("Error", "No QR-PNG found.\n" + res.stdout)

        # load into memory, then delete file
        with open(qr_path, "rb") as f:
            data = f.read()
        try: os.remove(qr_path)
        except: pass

        img = Image.open(io.BytesIO(data)).resize((300,300), Image.NEAREST)
        self.qr_imgtk = ImageTk.PhotoImage(img)
        self.qr_label.config(image=self.qr_imgtk)

        def clear():
            self.qr_label.config(image="")
        self.after(15000, clear)

    def _build_decrypt(self, f):
        ttk.Label(f, text="Encrypted File:").grid(row=0, column=0, sticky="w")
        self.dec_input = ttk.Entry(f, width=50); self.dec_input.grid(row=0, column=1, padx=5)
        ttk.Button(f, text="Browse…", command=self._browse_dec).grid(row=0, column=2)
        ttk.Button(f, text="Decrypt", command=self._decrypt).grid(row=1, column=1, pady=10)

    def _browse_dec(self):
        p = filedialog.askopenfilename(filetypes=[("ENC files","*.enc")])
        if p:
            self.dec_input.delete(0, tk.END)
            self.dec_input.insert(0, p)

    def _decrypt(self):
        inp = self.dec_input.get()
        if not inp:
            return messagebox.showerror("Error", "Select an .enc file.")

        proc = subprocess.Popen([RUST_BINARY, "decrypt", "--input", inp],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                text=True,
                                bufsize=1,
                                creationflags=CREATE_NO_WINDOW)

        last = ""
        for line in proc.stdout:
            last = line.strip()
            if line.startswith("Enter AES key"):
                key = simpledialog.askstring("Key Entry", last, show="*")
                if key is None:
                    proc.kill()
                    return
                proc.stdin.write(key + "\n")
                proc.stdin.flush()

        proc.wait()
        # On success or final failure, the .enc is already deleted by Rust.
        if proc.returncode == 0:
            messagebox.showinfo("Success", f"Decrypted to:\n{last}")
        else:
            messagebox.showerror("Failure", last or "Decryption failed")

if __name__ == "__main__":
    QRGuardApp().mainloop()
