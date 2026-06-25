# sudo python3 kguard_gui.py

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font
import subprocess
import threading
import os
import sys
import signal
import time
import json
from pathlib import Path
from datetime import datetime
from PIL import Image, ImageTk 

if os.geteuid() != 0:
    try:
        # Re-execute the current script using sudo and the same python interpreter
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
    except Exception as e:
        print(f"Failed to automatically elevate to sudo: {e}")
        sys.exit(1)

KGUARD_DIR    = Path(__file__).parent
MONITOR_BIN   = KGUARD_DIR / "monitor"
GRAPH_ENGINE  = KGUARD_DIR / "graphengine.py"
ML_DETECTOR   = KGUARD_DIR / "ml_detector.py"
VIEW_GRAPH    = KGUARD_DIR / "view_graph.py"
GEXF_FILE     = KGUARD_DIR / "system_behavior_graph.gexf"
GRAPH_PNG     = KGUARD_DIR / "graph.png"


BG  = "#0d1117" 
PANEL  = "#161b22"   
BORDER ="#30363d"   
ACCENT ="#58a6ff"   
GREEN = "#3fb950"
RED = "#f85149"
YELLOW = "#d29922"
TEXT  = "#e6edf3"
TEXT_DIM = "#8b949e"
FONT_MONO = ("Consolas", 10) if sys.platform == "win32" else ("Monospace", 10)
FONT_UI = ("Segoe UI", 10) if sys.platform == "win32" else ("Sans", 10)
FONT_TITLE = ("Segoe UI", 13, "bold") if sys.platform == "win32" else ("Sans", 13, "bold")

#helper functions
def ts():
    return datetime.now().strftime("%H:%M:%S")

def label(parent, text, **kw):
    return tk.Label(parent, text=text, bg=BG, fg=TEXT, font=FONT_UI, **kw)

def dim_label(parent, text, **kw):
    return tk.Label(parent, text=text, bg=BG, fg=TEXT_DIM, font=FONT_UI, **kw)


class KGuardGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("K-Guard  —  eBPF Intrusion Detection System")
        self.root.configure(bg=BG)
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)

        # Process handles
        self._monitor_proc  = None   # C monitor binary
        self._engine_proc   = None   # graphengine.py
        self._pipe_thread   = None
        self._running       = False

        # Live stats
        self._event_count   = tk.IntVar(value=0)
        self._node_count    = tk.IntVar(value=0)
        self._edge_count    = tk.IntVar(value=0)
        self._alert_count   = tk.IntVar(value=0)
        self._status_text   = tk.StringVar(value="Idle")

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)


    def _build_ui(self):
        # Top bar
        self._build_topbar()

        # Main body: left controls + right notebook
        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        self._build_left_panel(body)
        self._build_right_panel(body)

    def _build_topbar(self):
        bar = tk.Frame(self.root, bg=PANEL, height=52)
        bar.pack(fill=tk.X, padx=0, pady=0)
        bar.pack_propagate(False)

        tk.Label(bar, text="⬡  K-Guard", bg=PANEL, fg=ACCENT,
                 font=FONT_TITLE).pack(side=tk.LEFT, padx=16, pady=12)

        tk.Label(bar, text="eBPF  ·  Causal Provenance  ·  Isolation Forest",
                 bg=PANEL, fg=TEXT_DIM, font=FONT_UI).pack(side=tk.LEFT, padx=4)

        # Status indicator (right side)
        self._status_dot = tk.Label(bar, text="●", bg=PANEL, fg=TEXT_DIM, font=("", 14))
        self._status_dot.pack(side=tk.RIGHT, padx=(0, 12))
        tk.Label(bar, textvariable=self._status_text,
                 bg=PANEL, fg=TEXT_DIM, font=FONT_UI).pack(side=tk.RIGHT, padx=4)

    def _build_left_panel(self, parent):
        left = tk.Frame(parent, bg=BG, width=220)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10), pady=10)
        left.pack_propagate(False)

        self._section(left, "STAGE 1  —  CAPTURE")

        self._btn_start = self._button(left, "▶  Start Monitor",
                                       GREEN, self._start_monitor)
        self._btn_start.pack(fill=tk.X, pady=(0, 4))

        self._btn_stop = self._button(left, "■  Stop & Save Graph",
                                      RED, self._stop_monitor, state=tk.DISABLED)
        self._btn_stop.pack(fill=tk.X, pady=(0, 12))

        self._section(left, "STAGE 2  —  ANALYZE")

        self._button(left, "⚙  Run ML Detector",
                     ACCENT, self._run_ml).pack(fill=tk.X, pady=(0, 12))

        self._section(left, "STAGE 3  —  VISUALIZE")

        self._button(left, "🗺  Render Graph",
                     YELLOW, self._render_graph).pack(fill=tk.X, pady=(0, 20))

        self._section(left, "LIVE STATS")
        self._stat_row(left, "Events captured",  self._event_count)
        self._stat_row(left, "Graph nodes",       self._node_count)
        self._stat_row(left, "Graph edges",       self._edge_count)
        self._stat_row(left, "Anomalies found",   self._alert_count)

        tk.Frame(left, bg=BORDER, height=1).pack(fill=tk.X, pady=12)
        self._gexf_label = dim_label(left, self._gexf_status())
        self._gexf_label.pack(anchor="w")
        self._poll_gexf_status()

    def _build_right_panel(self, parent):
        right = tk.Frame(parent, bg=BG)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=10)

        nb = ttk.Notebook(right)
        nb.pack(fill=tk.BOTH, expand=True)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook",       background=PANEL, borderwidth=0)
        style.configure("TNotebook.Tab",   background=PANEL, foreground=TEXT_DIM,
                        padding=[12, 6], font=FONT_UI)
        style.map("TNotebook.Tab",
                  background=[("selected", BG)],
                  foreground=[("selected", ACCENT)])

        # Tab 1: Live events
        t1 = self._tab_frame(nb)
        nb.add(t1, text="  Live Events  ")
        self._event_log = self._log_widget(t1)

        # Tab 2: Graph engine output
        t2 = self._tab_frame(nb)
        nb.add(t2, text="  Graph Engine  ")
        self._graph_log = self._log_widget(t2)

        # Tab 3: ML report
        t3 = self._tab_frame(nb)
        nb.add(t3, text="  ML Report  ")
        self._ml_log = self._log_widget(t3, fg=TEXT)

        # Tab 4: Graph image
        t4 = self._tab_frame(nb)
        nb.add(t4, text="  Provenance Graph  ")
        self._build_graph_tab(t4)

    def _build_graph_tab(self, parent):
        toolbar = tk.Frame(parent, bg=PANEL)
        toolbar.pack(fill=tk.X)
        self._button(toolbar, "⟳  Refresh", ACCENT,
                     self._load_graph_image, pad=6).pack(side=tk.LEFT, padx=6, pady=4)
        self._graph_info = dim_label(toolbar, "No graph rendered yet")
        self._graph_info.pack(side=tk.LEFT, padx=8)

        # Scrollable canvas
        frame = tk.Frame(parent, bg=BG)
        frame.pack(fill=tk.BOTH, expand=True)

        self._graph_canvas = tk.Canvas(frame, bg="#1a1a2e", highlightthickness=0)
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL,   command=self._graph_canvas.yview)
        hsb = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self._graph_canvas.xview)
        self._graph_canvas.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side=tk.RIGHT,  fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self._graph_canvas.pack(fill=tk.BOTH, expand=True)
        self._graph_img_ref = None  # prevent GC

    def _tab_frame(self, parent):
        f = tk.Frame(parent, bg=BG)
        f.pack(fill=tk.BOTH, expand=True)
        return f

    def _log_widget(self, parent, fg=None):
        w = scrolledtext.ScrolledText(
            parent, bg="#0d1117", fg=fg or TEXT_DIM,
            font=FONT_MONO, bd=0, wrap=tk.WORD,
            insertbackground=TEXT, relief=tk.FLAT)
        w.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        w.configure(state=tk.DISABLED)

        # Color tags
        w.tag_config("ts",      foreground=TEXT_DIM)
        w.tag_config("exec",    foreground=GREEN)
        w.tag_config("open",    foreground=ACCENT)
        w.tag_config("alert",   foreground=RED,    font=(*FONT_MONO[:2], "bold"))
        w.tag_config("warn",    foreground=YELLOW)
        w.tag_config("info",    foreground=TEXT)
        w.tag_config("dim",     foreground=TEXT_DIM)
        w.tag_config("heading", foreground=ACCENT, font=(*FONT_MONO[:2], "bold"))
        return w

    def _button(self, parent, text, color, cmd, state=tk.NORMAL, pad=8):
        return tk.Button(parent, text=text, bg=PANEL, fg=color,
                         activebackground=BORDER, activeforeground=color,
                         font=FONT_UI, bd=0, pady=pad, cursor="hand2",
                         command=cmd, state=state, relief=tk.FLAT,
                         highlightthickness=1, highlightbackground=BORDER)

    def _section(self, parent, title):
        tk.Label(parent, text=title, bg=BG, fg=TEXT_DIM,
                 font=("Consolas", 8) if sys.platform == "win32" else ("Monospace", 8)
                 ).pack(anchor="w", pady=(8, 4))

    def _stat_row(self, parent, label_text, var):
        row = tk.Frame(parent, bg=BG)
        row.pack(fill=tk.X, pady=1)
        tk.Label(row, text=label_text, bg=BG, fg=TEXT_DIM,
                 font=FONT_UI).pack(side=tk.LEFT)
        tk.Label(row, textvariable=var, bg=BG, fg=ACCENT,
                 font=(*FONT_UI[:2], "bold")).pack(side=tk.RIGHT)


    def _log(self, widget, text, tag="info"):
        """Thread-safe log append."""
        def _append():
            widget.configure(state=tk.NORMAL)
            widget.insert(tk.END, f"[{ts()}] ", "ts")
            widget.insert(tk.END, text + "\n", tag)
            widget.see(tk.END)
            widget.configure(state=tk.DISABLED)
        self.root.after(0, _append)

    def _log_raw(self, widget, text, tag="dim"):
        """Log without timestamp."""
        def _append():
            widget.configure(state=tk.NORMAL)
            widget.insert(tk.END, text + "\n", tag)
            widget.see(tk.END)
            widget.configure(state=tk.DISABLED)
        self.root.after(0, _append)

    def _clear_log(self, widget):
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.configure(state=tk.DISABLED)


    def _start_monitor(self):
        if self._running:
            return

        if not MONITOR_BIN.exists():
            messagebox.showerror("Binary not found",
                f"'{MONITOR_BIN}' not found.\nRun 'make' in the K-Guard directory first.")
            return

        # Check for sudo (eBPF needs root)
        if os.geteuid() != 0:
            messagebox.showwarning("Root required",
                "The eBPF monitor must run as root.\n"
                "Please restart with: sudo python3 kguard_gui.py")
            return

        self._running = True
        self._event_count.set(0)
        self._node_count.set(0)
        self._edge_count.set(0)
        self._clear_log(self._event_log)
        self._clear_log(self._graph_log)

        self._set_status("Capturing", GREEN)
        self._btn_start.configure(state=tk.DISABLED)
        self._btn_stop.configure(state=tk.NORMAL)

        self._log(self._event_log, "Starting eBPF monitor pipeline...", "info")
        self._log(self._graph_log, "Graph engine initializing...", "info")

        try:
            # monitor → graphengine.py (piped)
            self._monitor_proc = subprocess.Popen(
                [str(MONITOR_BIN)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            self._engine_proc = subprocess.Popen(
                [sys.executable, str(GRAPH_ENGINE)],
                stdin=self._monitor_proc.stdout,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            # Close monitor's stdout in parent so SIGPIPE propagates correctly
            self._monitor_proc.stdout.close()

        except Exception as e:
            self._log(self._event_log, f"Failed to start: {e}", "alert")
            self._running = False
            self._set_status("Error", RED)
            return

        # Thread to read graphengine output
        self._pipe_thread = threading.Thread(
            target=self._read_engine_output, daemon=True)
        self._pipe_thread.start()

        # Thread to read raw monitor events (for event tab)
        threading.Thread(target=self._read_monitor_stderr, daemon=True).start()

    def _read_engine_output(self):
        """Read graphengine.py stdout — parse node/edge counts."""
        for line in self._engine_proc.stdout:
            line = line.rstrip()
            if not line:
                continue

            # Parse graph stats
            if "Current Graph Scale:" in line:
                try:
                    parts = line.split(":")[-1].split(",")
                    nodes = int(parts[0].strip().split()[0])
                    edges = int(parts[1].strip().split()[0])
                    self.root.after(0, lambda n=nodes, e=edges: (
                        self._node_count.set(n), self._edge_count.set(e)))
                except (ValueError, IndexError):
                    pass

            # Route to graph log tab
            if "[GRAPH ADD]" in line:
                self._log_raw(self._graph_log, line, "info")
            elif "Scale:" in line:
                self._log_raw(self._graph_log, line, "dim")
            else:
                self._log_raw(self._graph_log, line, "dim")

        self._log(self._graph_log, "Graph engine exited.", "warn")

    def _read_monitor_stderr(self):
        """Read raw stderr from monitor binary (for event display)."""
        for line in self._monitor_proc.stderr:
            line = line.decode(errors="replace").rstrip()
            if line:
                self._log_raw(self._event_log, line, "dim")

    def _stop_monitor(self):
        if not self._running:
            return

        self._log(self._event_log, "Stopping monitor — saving graph...", "warn")
        self._log(self._graph_log, "Sending SIGINT to graph engine...", "warn")

        # SIGINT to graphengine triggers its KeyboardInterrupt → saves GEXF
        if self._engine_proc and self._engine_proc.poll() is None:
            self._engine_proc.send_signal(signal.SIGINT)

        if self._monitor_proc and self._monitor_proc.poll() is None:
            self._monitor_proc.terminate()

        self._running = False
        self._set_status("Idle", TEXT_DIM)
        self._btn_start.configure(state=tk.NORMAL)
        self._btn_stop.configure(state=tk.DISABLED)

        # Wait a moment then refresh GEXF status
        self.root.after(1500, self._refresh_gexf_label)
        self._log(self._event_log, "Monitor stopped. Graph saved.", "info")


    def _run_ml(self):
        if not GEXF_FILE.exists():
            messagebox.showwarning("No graph data",
                f"'{GEXF_FILE}' not found.\n"
                "Run Stage 1 first to capture events and build the graph.")
            return

        self._clear_log(self._ml_log)
        self._log(self._ml_log, "Running Isolation Forest anomaly detector...", "heading")

        def _run():
            try:
                result = subprocess.run(
                    [sys.executable, str(ML_DETECTOR)],
                    cwd=str(KGUARD_DIR),
                    capture_output=True, text=True
                )
                output = result.stdout + (result.stderr or "")
                alert_count = 0
                for line in output.splitlines():
                    if "ANOMALY DETECTED" in line or "⚠️" in line:
                        self._log_raw(self._ml_log, line, "alert")
                        alert_count += 1
                    elif "CRITICAL" in line or "🚨" in line:
                        self._log_raw(self._ml_log, line, "alert")
                    elif "->" in line:
                        self._log_raw(self._ml_log, line, "warn")
                    elif "---" in line:
                        self._log_raw(self._ml_log, line, "heading")
                    else:
                        self._log_raw(self._ml_log, line, "info")

                self.root.after(0, lambda: self._alert_count.set(alert_count))

                if alert_count == 0:
                    self._log(self._ml_log, "✓ No anomalies detected.", "info")
                else:
                    self._log(self._ml_log,
                              f"⚠  {alert_count} anomal{'y' if alert_count==1 else 'ies'} flagged.",
                              "alert")
            except Exception as e:
                self._log(self._ml_log, f"Error running detector: {e}", "alert")

        threading.Thread(target=_run, daemon=True).start()


    def _render_graph(self):
        if not GEXF_FILE.exists():
            messagebox.showwarning("No graph data",
                "Run Stage 1 first to generate graph data.")
            return

        self._set_status("Rendering...", YELLOW)

        def _run():
            try:
                result = subprocess.run(
                    [sys.executable, str(VIEW_GRAPH)],
                    cwd=str(KGUARD_DIR),
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    self.root.after(0, self._load_graph_image)
                    self.root.after(0, lambda: self._set_status("Idle", TEXT_DIM))
                else:
                    self.root.after(0, lambda: messagebox.showerror(
                        "Render failed", result.stderr))
                    self.root.after(0, lambda: self._set_status("Error", RED))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))

        threading.Thread(target=_run, daemon=True).start()

    def _load_graph_image(self):
        if not GRAPH_PNG.exists():
            self._graph_info.configure(text="graph.png not found — run Render Graph first")
            return
        try:
            img = Image.open(GRAPH_PNG)
            # Scale to fit canvas (max 1600px wide)
            w, h = img.size
            max_w = 1600
            if w > max_w:
                ratio = max_w / w
                img = img.resize((max_w, int(h * ratio)), Image.LANCZOS)

            photo = ImageTk.PhotoImage(img)
            self._graph_img_ref = photo  # prevent GC
            self._graph_canvas.configure(scrollregion=(0, 0, img.width, img.height))
            self._graph_canvas.delete("all")
            self._graph_canvas.create_image(0, 0, anchor=tk.NW, image=photo)
            self._graph_info.configure(
                text=f"graph.png  —  {img.width}×{img.height}px  "
                     f"(modified {datetime.fromtimestamp(GRAPH_PNG.stat().st_mtime).strftime('%H:%M:%S')})"
            )
        except Exception as e:
            self._graph_info.configure(text=f"Failed to load image: {e}")


    def _set_status(self, text, color):
        def _do():
            self._status_text.set(text)
            self._status_dot.configure(fg=color)
        self.root.after(0, _do)

    def _gexf_status(self):
        if GEXF_FILE.exists():
            mtime = datetime.fromtimestamp(GEXF_FILE.stat().st_mtime).strftime("%H:%M:%S")
            size_kb = GEXF_FILE.stat().st_size // 1024
            return f"system_behavior_graph.gexf\n{size_kb} KB  (saved {mtime})"
        return "No graph file yet."

    def _refresh_gexf_label(self):
        self._gexf_label.configure(text=self._gexf_status())

    def _poll_gexf_status(self):
        self._refresh_gexf_label()
        self.root.after(5000, self._poll_gexf_status)


    def _on_close(self):
        if self._running:
            if messagebox.askyesno("Quit", "Monitor is running. Stop it and quit?"):
                self._stop_monitor()
                self.root.after(800, self.root.destroy)
        else:
            self.root.destroy()


if __name__ == "__main__":
    try:
        from PIL import Image, ImageTk
    except ImportError:
        print("Pillow not installed. Run: pip install pillow")
        print("(Needed for graph image display in the GUI)")
        sys.exit(1)

    root = tk.Tk()
    app = KGuardGUI(root)
    root.mainloop()