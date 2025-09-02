#!/usr/bin/env python3
"""
YARA Rule Tester GUI (Tkinter)
- Load a YARA rules file and scan selected files
- Shows match results per file
"""
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import yara, os

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("YARA Rule Tester (Training)")
        self.geometry("720x480")
        self.rules = None

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)

        self.rule_lbl = ttk.Label(frm, text="No rules loaded")
        self.rule_lbl.pack(anchor="w")
        ttk.Button(frm, text="Load YARA Rules...", command=self.load_rules).pack(anchor="w", pady=(0,8))

        self.files = []
        ttk.Button(frm, text="Add Files...", command=self.add_files).pack(anchor="w")
        self.listbox = tk.Listbox(frm, height=8)
        self.listbox.pack(fill="x", pady=6)

        ttk.Button(frm, text="Scan", command=self.scan).pack(anchor="w", pady=6)

        self.out = tk.Text(frm, height=12)
        self.out.pack(fill="both", expand=True)

    def load_rules(self):
        path = filedialog.askopenfilename(title="Select .yar/.yara file", filetypes=[("YARA", "*.yar *.yara"),("All","*.*")])
        if not path: return
        try:
            self.rules = yara.compile(filepath=path)
            self.rule_lbl.config(text=f"Rules: {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("YARA Compile Error", str(e))

    def add_files(self):
        sel = filedialog.askopenfilenames(title="Select files to scan")
        for s in sel:
            self.files.append(s)
            self.listbox.insert("end", s)

    def scan(self):
        if not self.rules:
            messagebox.showwarning("No rules", "Load a YARA rules file first.")
            return
        if not self.files:
            messagebox.showwarning("No files", "Add files to scan.")
            return
        self.out.delete("1.0","end")
        for fp in self.files:
            try:
                matches = self.rules.match(fp)
                if matches:
                    self.out.insert("end", f"[MATCH] {fp}\n")
                    for m in matches:
                        self.out.insert("end", f"  - {m.rule} (tags={m.tags})\n")
                else:
                    self.out.insert("end", f"[OK]    {fp}\n")
            except Exception as e:
                self.out.insert("end", f"[ERR]   {fp} -> {e}\n")

if __name__ == "__main__":
    App().mainloop()
