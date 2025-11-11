# File: EO_WeightLock_GUI.py
# Standalone weight-lock toggle GUI using Frida (16.x).
# Locks in-game weight at zero by intercepting the two write sites and zeroing the write register.
#
# Build (no console):
#   pyinstaller --noconsole --onefile EO_WeightLock_GUI.py
#
# Requirements:
#   pip install frida==16.* ttkthemes
# Run as Administrator if needed to attach.

import threading
import tkinter as tk
from tkinter import ttk, messagebox
from ttkthemes import ThemedTk
import re

try:
    import frida
except Exception as e:
    raise SystemExit(f"Frida import failed: {e}")

APP_TITLE = "EO Weight Lock"
# Process to attach (Windows typically shows the exe name for the process too)
DEFAULT_PROCESS = "Endless.exe"

# >>> Correct default RVAs from your v13 script:
DEFAULT_OFFSETS_TEXT = "0x100DF5, 0x100454"

class WeightLock:
    def __init__(self, process_name: str, log_fn):
        self.process_name = process_name
        self.log = log_fn
        self._session = None
        self._script = None
        self._lock = threading.Lock()

    def _build_js(self, offs_hex_list):
        # Use the exe module explicitly; fallback to main module if the name differs
        js = f"""
        (function() {{
            var mod = null;
            try {{
                mod = Process.getModuleByName("Endless.exe");
            }} catch (e) {{
                var mods = Process.enumerateModules();
                mod = mods.length ? mods[0] : null;
            }}
            if (!mod) {{
                throw new Error("Could not resolve Endless.exe (or main) module.");
            }}
            var base = mod.base;

            // Offsets provided by Python
            var OFFS = [{", ".join(f"ptr('{o}')" for o in offs_hex_list)}];

            OFFS.forEach(function(rel) {{
                var addr = base.add(rel);
                try {{
                    Interceptor.attach(addr, {{
                        onEnter: function (args) {{
                            // Force weight write register to zero (x86/x64 safe).
                            if (this.context.eax !== undefined) {{
                                this.context.eax = 0;
                            }} else if (this.context.rax !== undefined) {{
                                this.context.rax = ptr(0);
                            }}
                        }}
                    }});
                }} catch (e) {{
                    send({{type: "weight-lock-hook-error", address: addr.toString(), error: e.toString()}});
                }}
            }});

            send({{type: "weight-lock-ready", count: OFFS.length}});
        }})();
        """.strip()
        return js

    def enable(self, offsets):
        with self._lock:
            if self._session is not None:
                self.log("Already enabled.")
                return

            # Normalize tokens → hex strings
            offs_hex = []
            for raw in offsets:
                s = str(raw).strip()
                if s.lower().startswith("0x"):
                    offs_hex.append(s)
                else:
                    offs_hex.append(hex(int(s)))

            try:
                # Attach to process
                self._session = frida.attach(self.process_name)
            except Exception as e:
                self._session = None
                raise RuntimeError(f"Failed to attach to {self.process_name}: {e}")

            js = self._build_js(offs_hex)

            def on_message(message, data):
                try:
                    if message.get("type") == "send":
                        payload = message.get("payload", {})
                        typ = payload.get("type")
                        if typ == "weight-lock-ready":
                            self.log(f"Weight lock enabled on {payload.get('count')} address(es).")
                        elif typ == "weight-lock-hook-error":
                            self.log(f"Hook failed @ {payload.get('address')}: {payload.get('error')}")
                    elif message.get("type") == "error":
                        self.log(f"Script error: {message}")
                except Exception as e:
                    self.log(f"on_message error: {e}")

            try:
                self._script = self._session.create_script(js)
                self._script.on("message", on_message)
                self._script.load()
                self.log("Hooks installed (listening).")
            except Exception as e:
                try:
                    if self._script: self._script.unload()
                except Exception:
                    pass
                try:
                    if self._session: self._session.detach()
                except Exception:
                    pass
                self._script = None
                self._session = None
                raise RuntimeError(f"Failed to load hook script: {e}")

    def disable(self):
        with self._lock:
            ok = True
            try:
                if self._script:
                    self._script.unload()
            except Exception as e:
                ok = False
            finally:
                self._script = None

            try:
                if self._session:
                    self._session.detach()
            except Exception as e:
                ok = False
            finally:
                self._session = None

            self.log("Weight lock disabled." if ok else "Disabled with warnings.")

class App:
    def __init__(self):
        self.root = ThemedTk(theme="black")
        self.root.title(APP_TITLE)
        self.root.geometry("520x360")
        self.root.minsize(480, 340)

        self.process_var = tk.StringVar(value=DEFAULT_PROCESS)
        self.offsets_var = tk.StringVar(value=DEFAULT_OFFSETS_TEXT)
        self.status_var = tk.StringVar(value="Idle.")

        self.lock = WeightLock(self.process_var.get(), self._log)
        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 10, "pady": 8}
        frm = ttk.Frame(self.root)
        frm.pack(fill="both", expand=True)
        row = 0

        ttk.Label(frm, text="Process name:").grid(row=row, column=0, sticky="w", **pad)
        self.proc_entry = ttk.Entry(frm, textvariable=self.process_var, width=28)
        self.proc_entry.grid(row=row, column=1, sticky="we", **pad)
        frm.columnconfigure(1, weight=1)

        row += 1
        ttk.Label(frm, text="Weight write RVAs (comma-sep):").grid(row=row, column=0, sticky="w", **pad)
        self.offs_entry = ttk.Entry(frm, textvariable=self.offsets_var)
        self.offs_entry.grid(row=row, column=1, sticky="we", **pad)

        row += 1
        btns = ttk.Frame(frm); btns.grid(row=row, column=0, columnspan=2, sticky="w", **pad)
        self.enable_btn = ttk.Button(btns, text="Enable Weight Lock", command=self.on_enable)
        self.disable_btn = ttk.Button(btns, text="Disable", command=self.on_disable, state=tk.DISABLED)
        self.enable_btn.pack(side="left", padx=(0, 8)); self.disable_btn.pack(side="left")

        row += 1
        ttk.Label(frm, text="Status:").grid(row=row, column=0, sticky="nw", **pad)
        self.status_lbl = ttk.Label(frm, textvariable=self.status_var)
        self.status_lbl.grid(row=row, column=1, sticky="we", **pad)

        row += 1
        ttk.Label(frm, text="Log:").grid(row=row, column=0, sticky="nw", **pad)
        self.log_txt = tk.Text(frm, height=10, state="disabled")
        self.log_txt.grid(row=row, column=1, sticky="nsew", **pad)
        frm.rowconfigure(row, weight=1)

        row += 1
        hint = ttk.Label(frm, text="Tip: Defaults use your v13 write RVAs.\nEXE: pyinstaller --noconsole --onefile EO_WeightLock_GUI.py", foreground="#66b")
        hint.grid(row=row, column=0, columnspan=2, sticky="w", padx=10, pady=(0,10))

        self.process_var.trace_add("write", self._on_process_change)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _on_process_change(self, *_):
        self.lock = WeightLock(self.process_var.get(), self._log)

    def _parse_offsets(self):
        text = self.offsets_var.get().strip()
        if not text:
            raise ValueError("Provide at least one RVA (e.g., 0x100DF5).")
        parts = [p.strip() for p in text.split(",")]
        valid = []
        for p in parts:
            if re.fullmatch(r"(?i)0x[0-9a-f]+", p):
                valid.append(p)
            else:
                valid.append(str(int(p)))  # allow decimal
        return valid

    def _log(self, msg: str):
        self.status_var.set(msg)
        self.log_txt.config(state="normal")
        self.log_txt.insert("end", msg + "\n")
        self.log_txt.see("end")
        self.log_txt.config(state="disabled")

    def _threaded(self, target, on_ok=None, on_err=None):
        def run():
            try:
                target()
                if on_ok: self.root.after(0, on_ok)
            except Exception as e:
                if on_err:
                    self.root.after(0, lambda: on_err(e))
                else:
                    self.root.after(0, lambda: messagebox.showerror(APP_TITLE, str(e)))
        threading.Thread(target=run, daemon=True).start()

    def on_enable(self):
        try:
            offs = self._parse_offsets()
        except Exception as e:
            messagebox.showerror(APP_TITLE, str(e)); return
        self.enable_btn.config(state=tk.DISABLED)
        self._threaded(
            target=lambda: self.lock.enable(offs),
            on_ok=lambda: self.disable_btn.config(state=tk.NORMAL),
            on_err=lambda e: (self.enable_btn.config(state=tk.NORMAL),
                              messagebox.showerror(APP_TITLE, f"Enable failed:\n{e}"))
        )

    def on_disable(self):
        self.disable_btn.config(state=tk.DISABLED)
        self._threaded(
            target=self.lock.disable,
            on_ok=lambda: self.enable_btn.config(state=tk.NORMAL),
            on_err=lambda e: (self.enable_btn.config(state=tk.NORMAL),
                              messagebox.showwarning(APP_TITLE, f"Disable warnings:\n{e}"))
        )

    def on_close(self):
        try: self.lock.disable()
        except Exception: pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    App().run()
