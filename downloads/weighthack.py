# EO_WeightLock_GUI.py
# Compact red/black GUI, live weight readout, clickable link, no external icon files.
# Frida hooks the write sites and zeros EAX/RAX (same logic as your working version).
#
# Build:
#   pyinstaller --noconsole --onefile EO_WeightLock_GUI.py
#
# Requirements:
#   pip install frida==16.*

import threading
import tkinter as tk
from tkinter import ttk, messagebox
import webbrowser
import frida

PROCESS_NAME = "Endless.exe"
DEFAULT_ADDRS = [0x100DF5, 0x100454]  # RVAs from Endless.exe base (v12.2)
MORE_PROGS_URL = "https://eobots.github.io/EOBot/"

# ------------------------------ Frida Driver ------------------------------

class WeightLocker:
    def __init__(self, log_cb, weight_cb):
        self._session = None
        self._script = None
        self._enabled = False
        self._log = log_cb
        self._weight = weight_cb

    def _make_js(self, rvas):
        rva_list = ", ".join([f"ptr(0x{rv:x})" for rv in rvas])
        js = f"""
        (function() {{
            var WL = {{ lastVal: -1, lastTs: 0 }};
            function findBase() {{
                try {{
                    return Process.getModuleByName("{PROCESS_NAME}").base;
                }} catch (e) {{
                    var mods = Process.enumerateModules();
                    return mods.length ? mods[0].base : null;
                }}
            }}

            var base = findBase();
            if (!base) throw new Error("Could not resolve {PROCESS_NAME} module base.");

            var RVAS = [{rva_list}];

            function sampleWeight(ctx) {{
                var v = 0;
                try {{
                    if (ctx.eax !== undefined) v = ctx.eax|0;
                    else if (ctx.rax !== undefined) v = ctx.rax.toInt32();
                }} catch (e) {{ v = 0; }}
                var now = Date.now();
                if (v !== WL.lastVal || (now - WL.lastTs) > 300) {{
                    WL.lastVal = v; WL.lastTs = now;
                    send({{type:"weight-sample", value:v}});
                }}
            }}

            RVAS.forEach(function(rel) {{
                var addr = base.add(rel);
                try {{
                    Interceptor.attach(addr, {{
                        onEnter: function (args) {{
                            sampleWeight(this.context);
                            try {{
                                if (this.context.eax !== undefined) this.context.eax = 0;
                                if (this.context.rax !== undefined) this.context.rax = ptr(0);
                            }} catch (e) {{}}
                        }}
                    }});
                }} catch (e) {{
                    send({{type:"weight-lock-hook-error", address: addr.toString(), error: e.toString()}});
                }}
            }});

            send({{type:"weight-lock-ready", count: RVAS.length}});
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
                mtype = message.get("type")
                if mtype == "send":
                    payload = message.get("payload", {})
                    ptype = payload.get("type", "")
                    if ptype == "weight-lock-ready":
                        self._log(f"[frida] Weight lock enabled on {payload.get('count', '?')} addresses.")
                    elif ptype == "weight-lock-hook-error":
                        self._log(f"[frida] Hook failed @ {payload.get('address')} : {payload.get('error')}")
                    elif ptype == "weight-sample":
                        try:
                            v = int(payload.get("value", 0))
                        except Exception:
                            v = 0
                        self._weight(v)
                    else:
                        self._log(f"[frida] {payload}")
                elif mtype == "error":
                    self._log(f"[frida error] {message}")
                else:
                    self._log(f"[frida] {message}")

            self._script.on("message", on_message)
            self._script.load()
            self._enabled = True
            self._log("[ok] Hooks installed. Weight should now remain at 0.")
            return True

        except Exception as e:
            self._log(f"[error] Failed to create/load script: {e}")
            try:
                if self._session: self._session.detach()
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

# ------------------------------ GUI ------------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("EO Weight Lock")
        self.geometry("460x310")  # compact
        self.resizable(False, False)

        # Colors (red/black)
        self.bg = "#0b0b0e"
        self.panel = "#131318"
        self.accent = "#ef4444"
        self.text = "#f5f5f5"
        self.dim = "#9ca3af"

        self.configure(bg=self.bg)
        self._style_widgets()
        self._set_icon_generated()

        self.addr_var = tk.StringVar(value=", ".join([f"0x{x:X}" for x in DEFAULT_ADDRS]))
        self.status_var = tk.StringVar(value="OFF")
        self.weight_var = tk.StringVar(value="—")

        self.locker = WeightLocker(
            log_cb=lambda m: self.after(0, self._append_log, m),
            weight_cb=lambda v: self.after(0, self._set_weight, v)
        )

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # Programmatic window-bar icon (no files)
    def _set_icon_generated(self):
        icon = tk.PhotoImage(width=16, height=16)
        icon.put(self.bg, to=(0, 0, 16, 16))
        for x in range(16):
            icon.put(self.accent, (x, 0))
            icon.put(self.accent, (x, 15))
        for y in range(16):
            icon.put(self.accent, (0, y))
            icon.put(self.accent, (15, y))
        for y in range(6, 10):
            for x in range(6, 10):
                icon.put(self.accent, (x, y))
        self.iconphoto(True, icon)
        self._icon_ref = icon  # keep ref

    def _style_widgets(self):
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("TFrame", background=self.bg)
        style.configure("TLabelframe", background=self.panel, foreground=self.text, borderwidth=1)
        style.configure("TLabelframe.Label", background=self.panel, foreground=self.text)
        style.configure("TLabel", background=self.bg, foreground=self.text, font=("Segoe UI", 9))
        style.configure("Hint.TLabel", background=self.bg, foreground=self.dim, font=("Segoe UI", 9))
        style.configure("Small.TLabel", background=self.bg, foreground=self.text, font=("Segoe UI", 8))
        style.configure("Link.TLabel", background=self.bg, foreground=self.accent, font=("Segoe UI", 9, "underline"))
        style.configure("TButton",
                        background=self.accent, foreground="#000",
                        font=("Segoe UI Semibold", 9), padding=6, relief="flat")
        style.map("TButton", background=[("active", "#f87171")])
        style.configure("Secondary.TButton",
                        background="#27272a", foreground=self.text, font=("Segoe UI Semibold", 9), padding=6)
        style.map("Secondary.TButton", background=[("active", "#3f3f46")])
        style.configure("TEntry", fieldbackground="#18181b", foreground=self.text, insertcolor=self.text)

    def _build_ui(self):
        # Top row: Title + weight + status
        top = ttk.Frame(self, style="TFrame")
        top.pack(fill="x", padx=12, pady=(10, 4))
        ttk.Label(top, text="EO Weight Lock", font=("Segoe UI Semibold", 12)).pack(side="left")
        ttk.Label(top, text="Actual Weight:", style="TLabel").pack(side="left", padx=(8, 2))
        ttk.Label(top, textvariable=self.weight_var, style="TLabel").pack(side="left")

        status = ttk.Frame(top, style="TFrame")
        status.pack(side="right")
        self.dot = tk.Canvas(status, width=10, height=10, bg=self.bg, highlightthickness=0, bd=0)
        self.dot.pack(side="left", padx=(0, 6))
        self.dot_id = self.dot.create_oval(1, 1, 9, 9, fill="#7f1d1d", outline="")
        ttk.Label(status, textvariable=self.status_var, style="Small.TLabel").pack(side="left")

        # Link bar (always visible and clickable)
        linkbar = ttk.Frame(self, style="TFrame")
        linkbar.pack(fill="x", padx=12, pady=(0, 4))
        link = tk.Label(linkbar,
                        text=f"For More Programs: {MORE_PROGS_URL}",
                        fg=self.accent, bg=self.bg, cursor="hand2",
                        font=("Segoe UI", 9, "underline"))
        link.pack(side="left", anchor="w")
        link.bind("<Button-1>", lambda e: webbrowser.open(MORE_PROGS_URL))

        # Controls
        panel = ttk.LabelFrame(self, text=" Controls ", style="TLabelframe")
        panel.pack(fill="x", padx=12, pady=4, ipadx=6, ipady=6)

        r1 = ttk.Frame(panel, style="TFrame")
        r1.pack(fill="x")
        ttk.Label(r1, text="Write RVAs (comma-sep hex/dec):", style="TLabel").pack(side="left")
        self.addr_entry = ttk.Entry(r1, textvariable=self.addr_var, width=28)
        self.addr_entry.pack(side="left", padx=(6, 0))

        r2 = ttk.Frame(panel, style="TFrame")
        r2.pack(fill="x", pady=(6, 0))
        self.toggle_btn = ttk.Button(r2, text="Enable Weight Lock", command=self._toggle)
        self.toggle_btn.pack(side="left")
        ttk.Button(r2, text="Disable", style="Secondary.TButton", command=self._disable).pack(side="left", padx=6)

        # Hint
        hint = ttk.Label(self,
                         text="Pick an item up and drop it to force weight to lock at 0.",
                         style="Hint.TLabel")
        hint.pack(fill="x", padx=12, pady=(4, 2))

        # Log
        log_frame = ttk.LabelFrame(self, text=" Log ", style="TLabelframe")
        log_frame.pack(fill="both", expand=True, padx=12, pady=(4, 8))
        self.log = tk.Text(log_frame, height=6, wrap="word",
                           bg="#0f0f13", fg=self.text, insertbackground=self.text,
                           highlightthickness=0, bd=0)
        self.log.pack(fill="both", expand=True, padx=6, pady=6)
        self.log.configure(state="disabled")

    # -------------- UI helpers --------------

    def _append_log(self, msg: str):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _set_weight(self, v: int):
        self.weight_var.set(str(v))

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

    def _set_status(self, label, color):
        self.status_var.set(label)
        try:
            self.dot.itemconfig(self.dot_id, fill=color)
        except Exception:
            pass

    # -------------- Actions --------------

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

    def _on_close(self):
        try:
            self.locker.disable()
        except Exception:
            pass
        self.destroy()

# ------------------------------ Main ------------------------------

if __name__ == "__main__":
    app = App()
    app.mainloop()
