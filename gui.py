"""
combined_scanner_gui.py

Single-file GUI wrapper that loads your existing scanner6.py (from the uploaded path)
and runs it in-process. This file provides a pretty Tkinter GUI with Start/Stop,
config controls, live console, flow/blocked summaries, and safe shutdown.

It does NOT modify your original scanner file; instead it loads it dynamically
from the path (default: /mnt/data/scanner6.py). You can also edit the path
at the top of the GUI.

This script expects your scanner file to expose the following names (which
scanner6.py already provides):
  - packet_handler(pkt)
  - monitor()                # long-running monitoring loop
  - scapy (module)
  - api_client (object)
  - flows (dict)
  - blocked_ips (dict)
  - INTERFACE, USE_ML, ML_ONLY, MODEL_PATH, ml_model

When the GUI starts the scanner it will:
  - set INTERFACE, MODEL_PATH, USE_ML/ML_ONLY variables on the module
  - attempt to load the model if a path is provided
  - start monitor() in a daemon thread
  - start scapy.AsyncSniffer using packet_handler
  - monkeypatch print() inside the scanner module to surface logs in the GUI

How to run:
  python3 combined_scanner_gui.py

"""

import importlib.util
import sys
import os
import threading
import time
import queue
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from datetime import datetime

# default path to your uploaded scanner
ORIGINAL_SCANNER_PATH = "/mnt/c/Users/smayan/Desktop/threat-hunter/scanner.py"

# ------------------- helper: dynamic loader -------------------

def load_scanner_module(path=ORIGINAL_SCANNER_PATH, name="scanner6_loaded"):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Scanner file not found: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# ------------------- GUI / integration -------------------

class PrettyStyle:
    """Setup a dark mode theme"""
    BG_DARK = "#1e1e2e"
    BG_DARKER = "#181825"
    BG_LIGHTER = "#313244"
    TEXT_PRIMARY = "#cdd6f4"
    TEXT_SECONDARY = "#a6adc8"
    ACCENT = "#89b4fa"
    
    @staticmethod
    def apply(root):
        root.configure(bg=PrettyStyle.BG_DARK)
        style = ttk.Style(root)
        
        try:
            style.theme_use('clam')
        except Exception:
            pass
        
        # Configure dark theme
        style.configure('.', 
            background=PrettyStyle.BG_DARK,
            foreground=PrettyStyle.TEXT_PRIMARY,
            fieldbackground=PrettyStyle.BG_DARKER,
            font=("Segoe UI", 10))
        
        style.configure('TFrame', background=PrettyStyle.BG_DARK)
        style.configure('TLabelframe', 
            background=PrettyStyle.BG_DARK,
            foreground=PrettyStyle.TEXT_PRIMARY,
            bordercolor=PrettyStyle.BG_LIGHTER)
        style.configure('TLabelframe.Label',
            background=PrettyStyle.BG_DARK,
            foreground=PrettyStyle.ACCENT,
            font=("Segoe UI", 10, "bold"))
        
        style.configure('TButton', 
            background=PrettyStyle.BG_LIGHTER,
            foreground=PrettyStyle.TEXT_PRIMARY,
            bordercolor=PrettyStyle.ACCENT,
            padding=6)
        style.map('TButton',
            background=[('active', PrettyStyle.ACCENT)],
            foreground=[('active', PrettyStyle.BG_DARK)])
        
        style.configure('TLabel', 
            background=PrettyStyle.BG_DARK,
            foreground=PrettyStyle.TEXT_PRIMARY,
            padding=4)
        
        style.configure('TEntry', 
            fieldbackground=PrettyStyle.BG_DARKER,
            foreground=PrettyStyle.TEXT_PRIMARY,
            insertcolor=PrettyStyle.TEXT_PRIMARY,
            padding=4)
        
        style.configure('TCheckbutton',
            background=PrettyStyle.BG_DARK,
            foreground=PrettyStyle.TEXT_PRIMARY)
        
        style.configure('TNotebook',
            background=PrettyStyle.BG_DARK,
            bordercolor=PrettyStyle.BG_LIGHTER)
        style.configure('TNotebook.Tab',
            background=PrettyStyle.BG_LIGHTER,
            foreground=PrettyStyle.TEXT_SECONDARY,
            padding=[10, 2])
        style.map('TNotebook.Tab',
            background=[('selected', PrettyStyle.ACCENT)],
            foreground=[('selected', PrettyStyle.BG_DARK)])
        
        style.configure('Header.TLabel', 
            font=("Segoe UI", 12, "bold"),
            foreground=PrettyStyle.ACCENT,
            background=PrettyStyle.BG_DARK)


class CombinedScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Threat Hunter — Combined Scanner + GUI")
        self.geometry("1100x720")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        PrettyStyle.apply(self)

        # Runtime state
        self.scanner_mod = None
        self.sniffer = None
        self.monitor_thread = None
        self.running = False
        self.stdout_queue = queue.Queue()

        # UI variables
        self.path_var = tk.StringVar(value=ORIGINAL_SCANNER_PATH)
        self.iface_var = tk.StringVar(value="lo")
        self.model_var = tk.StringVar(value="")
        self.ml_only_var = tk.BooleanVar(value=False)

        # Build UI
        self._build_ui()

        # periodic poll for queue updates
        self.after(150, self._poll_stdout_queue)

    def _build_ui(self):
        # Top frame: header + controls
        header = ttk.Frame(self)
        header.pack(fill='x', padx=10, pady=8)

        ttk.Label(header, text="Scanner file:", style='Header.TLabel').pack(side='left')
        ttk.Entry(header, textvariable=self.path_var, width=62).pack(side='left', padx=(8,12))
        ttk.Button(header, text="Reload", command=self.reload_scanner).pack(side='left')

        frame2 = ttk.Frame(self)
        frame2.pack(fill='x', padx=10)

        ttk.Label(frame2, text="Interface:").pack(side='left')
        ttk.Entry(frame2, textvariable=self.iface_var, width=10).pack(side='left', padx=(6,12))

        ttk.Label(frame2, text="Model:").pack(side='left')
        ttk.Entry(frame2, textvariable=self.model_var, width=48).pack(side='left', padx=(6,6))
        ttk.Button(frame2, text="Browse", command=self.browse_model).pack(side='left')

        ttk.Checkbutton(frame2, text="ML-ONLY", variable=self.ml_only_var).pack(side='left', padx=(12,4))

        # Start/Stop buttons (prominent)
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill='x', padx=10, pady=(8,6))
        self.start_btn = ttk.Button(btn_frame, text="Start Scanner", command=self.start_scanner)
        self.start_btn.pack(side='left', padx=(0,6))
        self.stop_btn = ttk.Button(btn_frame, text="Stop Scanner", command=self.stop_scanner, state='disabled')
        self.stop_btn.pack(side='left')

        # Status label and indicators
        self.status_var = tk.StringVar(value="Stopped")
        ttk.Label(btn_frame, text="Status:").pack(side='left', padx=(20,6))
        self.status_lbl = ttk.Label(btn_frame, textvariable=self.status_var, foreground='red')
        self.status_lbl.pack(side='left')

        # Main area split into console (left) and summary (right)
        main = ttk.Frame(self)
        main.pack(fill='both', expand=True, padx=10, pady=6)

        # Console panel
        console_frame = ttk.LabelFrame(main, text="Console")
        console_frame.pack(side='left', fill='both', expand=True, padx=(0,8))
        self.console = scrolledtext.ScrolledText(
            console_frame, 
            wrap='none', 
            font=("Consolas", 10),
            bg="#181825",  # Dark background
            fg="#cdd6f4",  # Light text
            insertbackground="#cdd6f4",  # Cursor color
            selectbackground="#45475a",  # Selection background
            selectforeground="#cdd6f4",  # Selection text
            state='disabled'
        )
        self.console.pack(fill='both', expand=True)

        # Right panel: tabs for Flows / Blocks / Events
        right = ttk.Notebook(main, width=360)
        right.pack(side='right', fill='y')

        # Flows tab
        flows_frame = ttk.Frame(right)
        right.add(flows_frame, text='Flows')
        ttk.Label(flows_frame, text='Active flows (most recent):').pack(anchor='w', padx=6, pady=(6,0))
        self.flow_list = tk.Listbox(
            flows_frame, 
            height=12,
            bg="#181825",
            fg="#cdd6f4",
            selectbackground="#45475a",
            selectforeground="#cdd6f4",
            font=("Consolas", 9)
        )
        self.flow_list.pack(fill='both', expand=True, padx=6, pady=6)

        # Blocked IPs tab
        blocked_frame = ttk.Frame(right)
        right.add(blocked_frame, text='Blocked IPs')
        ttk.Label(blocked_frame, text='Currently blocked IPs:').pack(anchor='w', padx=6, pady=(6,0))
        self.blocked_list = tk.Listbox(
            blocked_frame, 
            height=8,
            bg="#181825",
            fg="#cdd6f4",
            selectbackground="#45475a",
            selectforeground="#cdd6f4",
            font=("Consolas", 9)
        )
        self.blocked_list.pack(fill='both', expand=True, padx=6, pady=6)
        btn_frame_blocked = ttk.Frame(blocked_frame)
        btn_frame_blocked.pack(fill='x', padx=6, pady=(0,8))
        ttk.Button(btn_frame_blocked, text='Unblock selected', command=self.unblock_selected).pack(side='left', padx=(0,6))
        ttk.Button(btn_frame_blocked, text='Unblock all', command=self.unblock_all).pack(side='left')

        # Events tab
        events_frame = ttk.Frame(right)
        right.add(events_frame, text='Events')
        ttk.Label(events_frame, text='Recent detections / chains:').pack(anchor='w', padx=6, pady=(6,0))
        self.events_box = scrolledtext.ScrolledText(
            events_frame, 
            height=12,
            bg="#181825",
            fg="#cdd6f4",
            insertbackground="#cdd6f4",
            selectbackground="#45475a",
            selectforeground="#cdd6f4",
            font=("Consolas", 9),
            state='disabled'
        )
        self.events_box.pack(fill='both', expand=True, padx=6, pady=6)

        # Bottom quick actions
        bottom = ttk.Frame(self)
        bottom.pack(fill='x', padx=10, pady=(0,10))
        ttk.Button(bottom, text='Tail log.csv', command=self.tail_log).pack(side='left')
        ttk.Button(bottom, text='Clear Console', command=self.clear_console).pack(side='left', padx=6)
        ttk.Button(bottom, text='Show stats', command=self.show_stats).pack(side='left', padx=6)

    # ------------------- utility UI functions -------------------

    def browse_model(self):
        p = filedialog.askopenfilename(title='Select model file', filetypes=[('joblib','*.joblib'),('all','*.*')])
        if p:
            self.model_var.set(p)

    def append_console(self, text):
        """Append text to console with ANSI color support"""
        import re
        
        # ANSI color code mapping to Tkinter colors
        ansi_colors = {
            '91': '#ff5555',  # bright red (FAIL)
            '92': '#50fa7b',  # bright green (OKGREEN)
            '93': '#f1fa8c',  # bright yellow (WARNING)
            '94': '#8be9fd',  # bright cyan (OKBLUE)
            '95': '#ff79c6',  # bright magenta (HEADER)
            '96': '#8be9fd',  # cyan (OKCYAN)
            '41': ('#ffffff', '#ff5555'),  # white on red (RED_BG)
        }
        
        # Configure tags if not already done
        if not hasattr(self, '_ansi_tags_configured'):
            self.console.tag_config('red', foreground='#ff5555')
            self.console.tag_config('green', foreground='#50fa7b')
            self.console.tag_config('yellow', foreground='#f1fa8c')
            self.console.tag_config('blue', foreground='#8be9fd')
            self.console.tag_config('magenta', foreground='#ff79c6')
            self.console.tag_config('cyan', foreground='#8be9fd')
            self.console.tag_config('bold', font=('Consolas', 10, 'bold'))
            self.console.tag_config('underline', underline=True)
            self.console.tag_config('red_bg', foreground='#ffffff', background='#ff5555', font=('Consolas', 10, 'bold'))
            self._ansi_tags_configured = True
        
        self.console.config(state='normal')
        
        # Parse ANSI codes
        ansi_pattern = re.compile(r'\033\[([0-9;]+)m')
        parts = ansi_pattern.split(text)
        
        current_tags = []
        for i, part in enumerate(parts):
            if i % 2 == 0:  # Text content
                if part:
                    self.console.insert('end', part, tuple(current_tags) if current_tags else ())
            else:  # ANSI code
                codes = part.split(';')
                for code in codes:
                    if code == '0':  # Reset
                        current_tags = []
                    elif code == '1':  # Bold
                        if 'bold' not in current_tags:
                            current_tags.append('bold')
                    elif code == '4':  # Underline
                        if 'underline' not in current_tags:
                            current_tags.append('underline')
                    elif code == '91':  # Bright red
                        current_tags = [t for t in current_tags if t not in ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan']]
                        current_tags.append('red')
                    elif code == '92':  # Bright green
                        current_tags = [t for t in current_tags if t not in ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan']]
                        current_tags.append('green')
                    elif code == '93':  # Bright yellow
                        current_tags = [t for t in current_tags if t not in ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan']]
                        current_tags.append('yellow')
                    elif code == '94':  # Bright blue
                        current_tags = [t for t in current_tags if t not in ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan']]
                        current_tags.append('blue')
                    elif code == '95':  # Bright magenta
                        current_tags = [t for t in current_tags if t not in ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan']]
                        current_tags.append('magenta')
                    elif code == '96':  # Cyan
                        current_tags = [t for t in current_tags if t not in ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan']]
                        current_tags.append('cyan')
                    elif code == '41':  # Red background
                        current_tags = [t for t in current_tags if t != 'red_bg']
                        current_tags.append('red_bg')
        
        self.console.see('end')
        self.console.config(state='disabled')

    def clear_console(self):
        self.console.config(state='normal')
        self.console.delete('1.0', 'end')
        self.console.config(state='disabled')

    def tail_log(self):
        path = os.path.join(os.getcwd(), 'log.csv')
        if not os.path.exists(path):
            messagebox.showwarning('No log', f'log.csv not found in {os.getcwd()}')
            return
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[-200:]
        win = tk.Toplevel(self)
        win.title('log.csv (tail)')
        t = scrolledtext.ScrolledText(win, wrap='none', width=120, height=30)
        t.pack(fill='both', expand=True)
        t.insert('end', ''.join(lines))
        t.config(state='disabled')

    def show_stats(self):
        # quick summary from module (if loaded)
        if not self.scanner_mod:
            messagebox.showinfo('Stats', 'Scanner module not loaded')
            return
        flows = getattr(self.scanner_mod, 'flows', {})
        blocked = getattr(self.scanner_mod, 'blocked_ips', {})
        msg = f"Active flows: {len(flows)}\nBlocked IPs: {len(blocked)}"
        messagebox.showinfo('Stats', msg)

    def unblock_selected(self):
        if not self.scanner_mod:
            return
        sel = self.blocked_list.curselection()
        if not sel:
            return
        ip = self.blocked_list.get(sel[0])
        try:
            # call the module's unblock logic if it exists; else remove from dict
            if hasattr(self.scanner_mod, 'blocked_ips'):
                if ip in self.scanner_mod.blocked_ips:
                    del self.scanner_mod.blocked_ips[ip]
            if hasattr(self.scanner_mod, 'api_client') and hasattr(self.scanner_mod.api_client, 'send_unblock'):
                self.scanner_mod.api_client.send_unblock({'ip': ip})
            self.append_console(f"[GUI] Unblocked {ip}\n")
            self.refresh_blocked()
        except Exception as e:
            self.append_console(f"[GUI] Failed to unblock {ip}: {e}\n")

    def unblock_all(self):
        if not self.scanner_mod:
            return
        try:
            blocked = getattr(self.scanner_mod, 'blocked_ips', {})
            if not blocked:
                self.append_console("[GUI] No IPs to unblock.\n")
                return
            
            ips_to_unblock = list(blocked.keys())
            count = len(ips_to_unblock)
            
            for ip in ips_to_unblock:
                try:
                    if hasattr(self.scanner_mod, 'blocked_ips'):
                        if ip in self.scanner_mod.blocked_ips:
                            del self.scanner_mod.blocked_ips[ip]
                    if hasattr(self.scanner_mod, 'api_client') and hasattr(self.scanner_mod.api_client, 'send_unblock'):
                        self.scanner_mod.api_client.send_unblock({'ip': ip})
                except Exception as e:
                    self.append_console(f"[GUI] Failed to unblock {ip}: {e}\n")
            
            self.append_console(f"[GUI] Unblocked all {count} IP(s).\n")
            self.refresh_blocked()
        except Exception as e:
            self.append_console(f"[GUI] Failed to unblock all IPs: {e}\n")

    # ------------------- scanner integration -------------------

    def reload_scanner(self):
        path = self.path_var.get().strip()
        try:
            self.append_console(f"[GUI] Loading scanner from: {path}\n")
            self.scanner_mod = load_scanner_module(path, name='scanner6_embedded')
            # small default: ensure monitor doesn't auto-run; if scanner had a top-level start, don't invoke
            self.append_console('[GUI] scanner module loaded\n')
            # attempt to monkeypatch module print to capture logs
            def module_print(*args, **kwargs):
                sep = kwargs.get('sep', ' ')
                end = kwargs.get('end', '\n')
                try:
                    text = sep.join(map(str, args)) + end
                    self.append_console('[scanner] ' + text)
                except Exception:
                    pass
            try:
                setattr(self.scanner_mod, 'print', module_print)
            except Exception:
                pass

            # populate model path if defined in module
            if hasattr(self.scanner_mod, 'MODEL_PATH'):
                try:
                    self.model_var.set(getattr(self.scanner_mod, 'MODEL_PATH') or '')
                except Exception:
                    pass

            self.refresh_blocked()
            self.refresh_flows()
        except Exception as e:
            self.append_console(f"[GUI] Failed to load scanner: {e}\n")
            messagebox.showerror('Load Error', str(e))

    def _try_load_model(self, path):
        if not path:
            return
        try:
            import joblib
            self.append_console('[GUI] Loading ML model...\n')
            model = joblib.load(path)
            self.append_console('[GUI] Model loaded.\n')
            # attach to module if present
            if self.scanner_mod:
                setattr(self.scanner_mod, 'ml_model', model)
        except Exception as e:
            self.append_console(f"[GUI] Model load failed: {e}\n")

    def start_scanner(self):
        if self.running:
            return
        if not self.scanner_mod:
            try:
                self.reload_scanner()
            except Exception:
                return

        # set config values on module
        iface = self.iface_var.get().strip()
        modelp = self.model_var.get().strip()
        setattr(self.scanner_mod, 'INTERFACE', iface)
        if modelp:
            setattr(self.scanner_mod, 'MODEL_PATH', modelp)
            # try load model
            self._try_load_model(modelp)

        # set ML flags
        setattr(self.scanner_mod, 'ML_ONLY', bool(self.ml_only_var.get()))
        if self.ml_only_var.get():
            setattr(self.scanner_mod, 'USE_ML', True)

        # start monitor thread
        if hasattr(self.scanner_mod, 'monitor'):
            self.monitor_thread = threading.Thread(target=self.scanner_mod.monitor, daemon=True)
            self.monitor_thread.start()
            self.append_console('[GUI] Monitor thread started.\n')

        # start sniffer
        if hasattr(self.scanner_mod, 'scapy') and hasattr(self.scanner_mod, 'packet_handler'):
            scapy_mod = getattr(self.scanner_mod, 'scapy')
            try:
                self.sniffer = scapy_mod.AsyncSniffer(iface=iface, prn=self.scanner_mod.packet_handler, store=False)
                self.sniffer.start()
                self.append_console(f"[GUI] Sniffer started on {iface}\n")
            except Exception as e:
                self.append_console(f"[GUI] Failed to start sniffer: {e}\n")

        self.running = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_var.set('Running')
        self.status_lbl.config(foreground='green')

        # start updater thread to refresh UI lists periodically
        self.ui_updater = threading.Thread(target=self._ui_updater_loop, daemon=True)
        self.ui_updater.start()

    def stop_scanner(self):
        if not self.running:
            return
        # stop sniffer
        try:
            if self.sniffer:
                try:
                    self.sniffer.stop()
                    self.append_console('[GUI] Sniffer stopped.\n')
                except Exception as e:
                    self.append_console(f'[GUI] Error stopping sniffer: {e}\n')
                self.sniffer = None
        except Exception:
            pass

        # try to stop API client thread if present
        try:
            if self.scanner_mod and hasattr(self.scanner_mod, 'api_client'):
                try:
                    self.scanner_mod.api_client.running = False
                except Exception:
                    pass
        except Exception:
            pass

        self.running = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_var.set('Stopped')
        self.status_lbl.config(foreground='red')
        self.append_console('[GUI] Scanner stopped by user.\n')

    def _ui_updater_loop(self):
        while self.running:
            try:
                self.refresh_flows()
                self.refresh_blocked()
                time.sleep(1.0)
            except Exception:
                time.sleep(1.0)

    def refresh_flows(self):
        # show a subset of flow keys (module must expose flows dict)
        try:
            flows = getattr(self.scanner_mod, 'flows', {})
            items = list(flows.keys())[-30:][::-1]
            self.flow_list.delete(0, 'end')
            for k in items:
                # show a short representation
                try:
                    if isinstance(k, tuple):
                        self.flow_list.insert('end', f"{k[0]}:{k[2]} -> {k[1]}:{k[3]}")
                    else:
                        self.flow_list.insert('end', str(k))
                except Exception:
                    self.flow_list.insert('end', str(k))
        except Exception:
            pass

    def refresh_blocked(self):
        try:
            blocked = getattr(self.scanner_mod, 'blocked_ips', {})
            ips = list(blocked.keys())
            self.blocked_list.delete(0, 'end')
            for ip in ips:
                self.blocked_list.insert('end', ip)
        except Exception:
            pass

    def _poll_stdout_queue(self):
        # process queued text from module print shim (if used)
        try:
            while True:
                line = self.stdout_queue.get_nowait()
                self.append_console(line)
        except queue.Empty:
            pass
        self.after(150, self._poll_stdout_queue)

    # used by scanner module shim to write into GUI console
    def push_scanner_log(self, text):
        try:
            self.stdout_queue.put(text)
        except Exception:
            pass

    def on_close(self):
        if self.running:
            if not messagebox.askyesno('Quit', 'Scanner is running. Stop and exit?'):
                return
            self.stop_scanner()
            time.sleep(0.15)
        self.destroy()


# ------------------- bootstrap -------------------

def main():
    app = CombinedScannerApp()
    # attach a helper that the module can use: module_print will push text into GUI
    def set_module_print(gui_app: CombinedScannerApp, mod):
        def module_print(*args, **kwargs):
            sep = kwargs.get('sep', ' ')
            end = kwargs.get('end', '\n')
            try:
                text = sep.join(map(str, args)) + end
                gui_app.push_scanner_log('[scanner] ' + text)
            except Exception:
                pass
        try:
            setattr(mod, 'print', module_print)
        except Exception:
            pass

    # attempt to preload scanner module automatically (non-fatal)
    try:
        mod = load_scanner_module(ORIGINAL_SCANNER_PATH, name='scanner6_embedded')
        app.scanner_mod = mod
        # attach GUI push function as the module print
        set_module_print(app, mod)
        # copy default model path if module has it
        try:
            if hasattr(mod, 'MODEL_PATH'):
                app.model_var.set(getattr(mod, 'MODEL_PATH') or '')
        except Exception:
            pass
        app.append_console(f"[GUI] Preloaded scanner module from {ORIGINAL_SCANNER_PATH}\n")
        app.refresh_blocked()
    except Exception as e:
        app.append_console(f"[GUI] (preload) Failed to load scanner: {e}\n")

    app.mainloop()


if __name__ == '__main__':
    main()
