# EO_WeightLock_GUI.py
# Standalone weight-lock toggle using Frida. GUI-only; no terminal output required.
# Default write RVAs pulled from CeraBot v12.2: WEIGHT_WRITE_ADDRS = [0x100DF5, 0x100454]

import threading
import tkinter as tk
from tkinter import ttk, messagebox
import webbrowser
import frida
import time

PROCESS_NAME = "Endless.exe"
DEFAULT_ADDRS = [0x100DF5, 0x100454]  # RVAs from Endless.exe base (v12.2)

class WeightLocker:
    """
    Small helper managing a Frida session that hooks write instructions at the
    provided RVAs and forces the written register to 0, mirroring v12.2's logic.
    """
    def __init__(self, log_cb):
        self._session = None
        self._script = None
        self._enabled = False
        self._log = log_cb

    def _make_js(self, rvas):
        # Build a Frida script that: resolves Endless.exe base, iterates RVAs,
        # attaches Interceptor to each address, and zeros EAX/RAX before the write.
        # Works on 32/64-bit; we set whichever register exists in the context.
        rva_list = ", ".join([f"ptr(0x{rv:x})" for rv in rvas])
        js = f"""
        (function() {{
            function findBase() {{
                try {{
                    return Process.getModuleByName("{PROCESS_NAME}").base;
                }} catch (e) {{
                    var mods = Process.enumerateModules();
                    return mods.length ? mods[0].base : null;
                }}
            }}
            var base = findBase();
            if (!base) {{
                throw new Error("Could not resolve {PROCESS_NAME} module base.");
            }}

            var RVAS = [{rva_list}];
            RVAS.forEach(function(rel) {{
                var addr = base.add(rel);
                try {{
                    Interceptor.attach(addr, {{
                        onEnter: function (args) {{
                            try {{
                                if (this.context.eax !== undefined) {{
                                    this.context.eax = 0;
                                }}
                                if (this.context.rax !== undefined) {{
                                    this.context.rax = ptr(0);
                                }}
                            }} catch (e) {{
                                // Swallow per-call errors to keep hook alive
                            }}
                        }}
                    }});
                }} catch (e) {{
                    send({{type: "weight-lock-hook-error", address: addr.toString(), error: e.toString()}});
                }}
            }});

            send({{type: "weight-lock-ready", count: RVAS.length}});
        }})();
        """
        return js

    def enable(self, rvas):
        if self._enabled:
            return True

        try:
            self._session = frida.attach(PROCESS_NAME)
        except Exception as e:
            self._session = None
            self._log(f"[error] Unable to attach to {PROCESS_NAME}: {e}")
            return False

        try:
            js = self._make_js(rvas)
            self._script = self._session.create_script(js)

            def on_message(message, data):
                try:
                    mtype = message.get("type")
                    if mtype == "send":
                        payload = message.get("payload", {})
                        ptype = payload.get("type", "")
                        if ptype == "weight-lock-ready":
                            self._log(f"[frida] Weight lock enabled on {payload.get('count', '?')} addresses.")
                        elif ptype == "weight-lock-hook-error":
                            self._log(f"[frida] Hook failed @ {payload.get('address')} : {payload.get('error')}")
                        else:
                            self._log(f"[frida] {payload}")
                    elif mtype == "error":
                        self._log(f"[frida error] {message}")
                    else:
                        self._log(f"[frida] {message}")
                except Exception as e:
                    self._log(f"[error] Message handling: {e}")

            self._script.on("message", on_message)
            self._script.load()
            self._enabled = True
            self._log("[ok] Hooks installed. Weight should now remain at 0.")
            return True

        except Exception as e:
            self._log(f"[error] Failed to create/load script: {e}")
            try:
                if self._session:
                    self._session.detach()
            except Exception:
                pass
            self._session = None
            self._script = None
            return False

    def disable(self):
        ok = True
        if self._script is not None:
            try:
                self._script.unload()
            except Exception as e:
                self._log(f"[warn] Error unloading script: {e}")
                ok = False
            self._script = None
        if self._session is not None:
            try:
                self._session.detach()
            except Exception as e:
                self._log(f"[warn] Error detaching session: {e}")
                ok = False
            self._session = None
        if self._enabled:
            self._log("[ok] Hooks removed. Weight will behave normally.")
        self._enabled = False
        return ok

    @property
    def enabled(self):
        return self._enabled


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("EO Weight Lock")
        self.geometry("560x420")
        self.resizable(False, False)

        # Colors (red/black theme)
        self.bg = "#0b0b0e"
        self.panel = "#111116"
        self.accent = "#ef4444"
        self.text = "#f5f5f5"
        self.dim = "#a1a1aa"

        self.configure(bg=self.bg)
        self._style_widgets()

        self.locker = WeightLocker(self._log)

        self._build_ui()

        # default addresses
        self.addr_var.set(", ".join([f"0x{x:X}" for x in DEFAULT_ADDRS]))

        # on close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _style_widgets(self):
        style = ttk.Style(self)
        style.theme_use("default")

        style.configure("TFrame", background=self.bg)
        style.configure("Panel.TFrame", background=self.panel)
        style.configure("TLabel", background=self.bg, foreground=self.text, font=("Segoe UI", 10))
        style.configure("Heading.TLabel", background=self.bg, foreground=self.text, font=("Segoe UI Semibold", 14))
        style.configure("Small.TLabel", background=self.bg, foreground=self.dim, font=("Segoe UI", 9))
        style.configure("TButton",
                        background=self.accent, foreground="#000",
                        font=("Segoe UI Semibold", 10),
                        relief="flat", padding=8)
        style.map("TButton",
                  background=[("active", "#f87171")])
        style.configure("Secondary.TButton",
                        background="#27272a", foreground=self.text)
        style.map("Secondary.TButton",
                  background=[("active", "#3f3f46")])
        style.configure("TEntry", fieldbackground="#18181b", foreground=self.text, insertcolor=self.text)
        style.configure("TLabelframe", background=self.panel, foreground=self.text)
        style.configure("TLabelframe.Label", background=self.panel, foreground=self.text)

    def _build_ui(self):
        # Header
        header = ttk.Frame(self, style="TFrame")
        header.pack(fill="x", padx=16, pady=(16, 8))

        ttk.Label(header, text="EO Weight Lock", style="Heading.TLabel").pack(anchor="w")
        ttk.Label(header, text="Locks your in-game weight to 0 by intercepting write instructions (Frida-based).",
                  style="Small.TLabel").pack(anchor="w", pady=(2, 0))

        # Controls panel
        panel = ttk.LabelFrame(self, text=" Controls ", style="TLabelframe")
        panel.pack(fill="x", padx=16, pady=8, ipadx=8, ipady=8)

        row = ttk.Frame(panel, style="Panel.TFrame")
        row.pack(fill="x", padx=8, pady=6)

        ttk.Label(row, text="Write RVAs (from Endless.exe base, comma-separated hex or dec):").pack(anchor="w")
        self.addr_var = tk.StringVar()
        addr_entry = ttk.Entry(row, textvariable=self.addr_var, width=64)
        addr_entry.pack(anchor="w", pady=(4, 0))

        btns = ttk.Frame(panel, style="Panel.TFrame")
        btns.pack(fill="x", padx=8, pady=(8, 0))

        self.toggle_btn = ttk.Button(btns, text="Enable Weight Lock", command=self._toggle)
        self.toggle_btn.pack(side="left", padx=(0, 8))

        self.stop_btn = ttk.Button(btns, text="Disable", command=self._disable, style="Secondary.TButton")
        self.stop_btn.pack(side="left")

        # Status line
        status = ttk.Frame(self, style="TFrame")
        status.pack(fill="x", padx=16, pady=(8, 4))
        ttk.Label(status, text="Status:", style="TLabel").pack(side="left")

        self.dot = tk.Canvas(status, width=12, height=12, bg=self.bg, highlightthickness=0)
        self.dot.pack(side="left", padx=6)
        self.dot_id = self.dot.create_oval(2, 2, 10, 10, fill="#7f1d1d", outline="")

        self.status_var = tk.StringVar(value="OFF")
        self.status_lbl = ttk.Label(status, textvariable=self.status_var, style="TLabel")
        self.status_lbl.pack(side="left")

        # Log box
        log_frame = ttk.LabelFrame(self, text=" Log ", style="TLabelframe")
        log_frame.pack(fill="both", expand=True, padx=16, pady=8)

        self.log = tk.Text(log_frame, height=10, wrap="word",
                           bg="#0f0f13", fg=self.text, insertbackground=self.text,
                           highlightthickness=0, bd=0)
        self.log.pack(fill="both", expand=True, padx=8, pady=8)
        self.log.configure(state="disabled")

        # Link (clickable)
        link_frame = ttk.Frame(self, style="TFrame")
        link_frame.pack(fill="x", padx=16, pady=(0, 12))

        link = tk.Label(link_frame,
                        text="For More Programs: https://eobots.github.io/EOBot/",
                        fg=self.accent, bg=self.bg, cursor="hand2", font=("Segoe UI", 10, "underline"))
        link.pack(anchor="w")
        link.bind("<Button-1>", lambda e: webbrowser.open("https://eobots.github.io/EOBot/"))

        self._refresh_ui()

    def _log(self, msg):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _parse_addrs(self):
        raw = self.addr_var.get().strip()
        if not raw:
            return []
        out = []
        for part in raw.split(","):
            s = part.strip()
            if not s:
                continue
            try:
                if s.lower().startswith("0x"):
                    out.append(int(s, 16))
                else:
                    out.append(int(s, 10))
            except ValueError:
                raise ValueError(f"Bad address: {s}")
        return out

    def _toggle(self):
        if self.locker.enabled:
            self._disable()
            return

        try:
            rvas = self._parse_addrs()
            if not rvas:
                messagebox.showerror("Error", "Please provide at least one RVA.")
                return
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        # Enable in a thread so UI doesn't freeze
        def worker():
            self._set_status("WORKING", "#92400e")
            ok = self.locker.enable(rvas)
            if ok and self.locker.enabled:
                self._set_status("ON", "#16a34a")
                self.toggle_btn.configure(text="Disable Weight Lock")
            else:
                self._set_status("OFF", "#7f1d1d")
                self.toggle_btn.configure(text="Enable Weight Lock")

        threading.Thread(target=worker, daemon=True).start()

    def _disable(self):
        def worker():
            self._set_status("WORKING", "#92400e")
            self.locker.disable()
            self._set_status("OFF", "#7f1d1d")
            self.toggle_btn.configure(text="Enable Weight Lock")
        threading.Thread(target=worker, daemon=True).start()

    def _set_status(self, label, color):
        self.status_var.set(label)
        try:
            self.dot.itemconfig(self.dot_id, fill=color)
        except Exception:
            pass
        self._refresh_ui()

    def _refresh_ui(self):
        # Buttons enable/disable based on state
        if self.locker.enabled:
            self.toggle_btn.configure(text="Disable Weight Lock")
        else:
            self.toggle_btn.configure(text="Enable Weight Lock")

    def _on_close(self):
        try:
            self.locker.disable()
        except Exception:
            pass
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.mainloop()
