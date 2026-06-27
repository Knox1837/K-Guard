# sudo python3 kguard_gui.py

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import threading
import os
import sys
import signal
import time
import json
import webbrowser
from pathlib import Path
from datetime import datetime

if "SUDO_USER" in os.environ:
    os.environ.setdefault("DISPLAY", ":0")
    xauth = f"/home/{os.environ['SUDO_USER']}/.Xauthority"
    if Path(xauth).exists():
        os.environ["XAUTHORITY"] = xauth

if os.geteuid() != 0:
    try:
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
    except Exception as e:
        print(f"Failed to elevate to sudo: {e}")
        sys.exit(1)

KGUARD_DIR   = Path(__file__).parent
MONITOR_BIN  = KGUARD_DIR / "monitor"
GRAPH_ENGINE = KGUARD_DIR / "src/user/graphengine.py"
ML_DETECTOR  = KGUARD_DIR / "ml_detector.py"
VIEW_GRAPH   = KGUARD_DIR / "view_graph.py"
GEXF_FILE    = KGUARD_DIR / "system_behavior_graph.gexf"
HTML_FILE    = KGUARD_DIR / "kguard_interactive_graph.html"

BG        = "#0d1117"
PANEL     = "#161b22"
BORDER    = "#30363d"
ACCENT    = "#58a6ff"
GREEN     = "#3fb950"
RED       = "#f85149"
YELLOW    = "#d29922"
TEXT      = "#e6edf3"
TEXT_DIM  = "#8b949e"
FONT_MONO = ("Monospace", 10)
FONT_UI   = ("Sans", 10)
FONT_TITLE= ("Sans", 13, "bold")
FONT_TINY = ("Monospace", 8)

def ts():
    return datetime.now().strftime("%H:%M:%S")


class KGuardGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("K-Guard  —  eBPF Intrusion Detection System")
        self.root.configure(bg=BG)
        self.root.geometry("1280x820")
        self.root.minsize(960, 640)

        # Process handles
        self._monitor_proc  = None
        self._engine_proc   = None
        self._running       = False

        # Live stats
        self._event_count  = tk.IntVar(value=0)
        self._node_count   = tk.IntVar(value=0)
        self._edge_count   = tk.IntVar(value=0)
        self._alert_count  = tk.IntVar(value=0)
        self._status_text  = tk.StringVar(value="Idle")

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        self._build_topbar()
        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self._build_left_panel(body)
        self._build_right_panel(body)

    def _build_topbar(self):
        bar = tk.Frame(self.root, bg=PANEL, height=52)
        bar.pack(fill=tk.X)
        bar.pack_propagate(False)
        tk.Label(bar, text="⬡  K-Guard", bg=PANEL, fg=ACCENT,
                 font=FONT_TITLE).pack(side=tk.LEFT, padx=16, pady=12)
        tk.Label(bar, text="eBPF  ·  Causal Provenance  ·  Isolation Forest",
                 bg=PANEL, fg=TEXT_DIM, font=FONT_UI).pack(side=tk.LEFT, padx=4)
        self._status_dot = tk.Label(bar, text="●", bg=PANEL, fg=TEXT_DIM, font=("", 14))
        self._status_dot.pack(side=tk.RIGHT, padx=(0, 12))
        tk.Label(bar, textvariable=self._status_text,
                 bg=PANEL, fg=TEXT_DIM, font=FONT_UI).pack(side=tk.RIGHT, padx=4)

    def _build_left_panel(self, parent):
        left = tk.Frame(parent, bg=BG, width=230)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10), pady=10)
        left.pack_propagate(False)

        # Stage 1
        self._section(left, "STAGE 1  —  CAPTURE")
        self._btn_start = self._btn(left, "▶  Start Monitor", GREEN, self._start_monitor)
        self._btn_start.pack(fill=tk.X, pady=(0, 4))
        self._btn_stop = self._btn(left, "■  Stop & Save Graph", RED, self._stop_monitor,
                                   state=tk.DISABLED)
        self._btn_stop.pack(fill=tk.X, pady=(0, 12))

        # Stage 2
        self._section(left, "STAGE 2  —  ANALYZE")
        self._btn_ml = self._btn(left, "⚙  Run ML Detector", ACCENT, self._run_ml)
        self._btn_ml.pack(fill=tk.X, pady=(0, 12))

        # Stage 3
        self._section(left, "STAGE 3  —  VISUALIZE")
        self._btn_render = self._btn(left, "🗺  Render Graph", YELLOW, self._render_graph)
        self._btn_render.pack(fill=tk.X, pady=(0, 4))
        self._btn_browser = self._btn(left, "🌐  Open in Browser", TEXT_DIM,
                                      self._open_in_browser)
        self._btn_browser.pack(fill=tk.X, pady=(0, 20))

        # Live stats
        self._section(left, "LIVE STATS")
        self._stat_row(left, "Events captured",  self._event_count)
        self._stat_row(left, "Graph nodes",       self._node_count)
        self._stat_row(left, "Graph edges",       self._edge_count)
        self._stat_row(left, "Anomalies found",   self._alert_count)

        tk.Frame(left, bg=BORDER, height=1).pack(fill=tk.X, pady=12)
        self._gexf_label = tk.Label(left, text=self._gexf_status(),
                                    bg=BG, fg=TEXT_DIM, font=FONT_TINY,
                                    justify=tk.LEFT, anchor="w")
        self._gexf_label.pack(anchor="w")
        self._poll_gexf_status()

    def _build_right_panel(self, parent):
        right = tk.Frame(parent, bg=BG)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=10)

        nb = ttk.Notebook(right)
        nb.pack(fill=tk.BOTH, expand=True)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook",     background=PANEL, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=TEXT_DIM,
                        padding=[12, 6], font=FONT_UI)
        style.map("TNotebook.Tab",
                  background=[("selected", BG)],
                  foreground=[("selected", ACCENT)])

        t1 = self._tab_frame(nb);  nb.add(t1, text="  Live Events  ")
        self._event_log = self._logw(t1)

        t2 = self._tab_frame(nb);  nb.add(t2, text="  Graph Engine  ")
        self._graph_log = self._logw(t2)

        t3 = self._tab_frame(nb);  nb.add(t3, text="  ML Report  ")
        self._ml_log = self._logw(t3, fg=TEXT)

        t4 = self._tab_frame(nb);  nb.add(t4, text="  Provenance Graph  ")
        self._build_graph_tab(t4)

        self._nb = nb

    def _build_graph_tab(self, parent):
        bar = tk.Frame(parent, bg=PANEL)
        bar.pack(fill=tk.X)
        self._btn(bar, "⟳  Re-render & Refresh", ACCENT,
                self._refresh_graph_view, pad=6).pack(side=tk.LEFT, padx=6, pady=4)
        self._btn(bar, "🌐  Open in Browser", TEXT,
                self._open_in_browser, pad=6).pack(side=tk.LEFT, padx=4, pady=4)
        self._graph_info = tk.Label(bar, text="No graph rendered yet.",
                                    bg=PANEL, fg=TEXT_DIM, font=FONT_UI)
        self._graph_info.pack(side=tk.LEFT, padx=12)

        legend_frame = tk.Frame(parent, bg=PANEL)
        legend_frame.pack(fill=tk.X)
        for color, label_text in [
            ("#ff7675", "● Process"),
            ("#74b9ff", "◆ Binary"),
            ("#55efc4", "■ Data File"),
            ("#a29bfe", "▲ Network"),
        ]:
            tk.Label(legend_frame, text=label_text, bg=PANEL, fg=color,
                    font=FONT_UI).pack(side=tk.LEFT, padx=10, pady=2)

        tk.Frame(parent, bg=BORDER, height=1).pack(fill=tk.X)

        self._html_frame = None   # pywebview opens a separate window, not embedded
        info_canvas = tk.Canvas(parent, bg="#0d1117", highlightthickness=0)
        info_canvas.pack(fill=tk.BOTH, expand=True)
        self._graph_placeholder = info_canvas
        self._draw_graph_placeholder("Click Render Graph  to generate the interactive graph.")

    def _draw_graph_placeholder(self, message):
        c = self._graph_placeholder
        c.delete("all")
        # Get canvas size (may be 1x1 until drawn; schedule after layout)
        def _draw():
            w = c.winfo_width() or 800
            h = c.winfo_height() or 500
            c.create_text(w//2, h//2 - 20, text="⬡", fill=ACCENT,
                          font=("Sans", 48))
            c.create_text(w//2, h//2 + 40, text=message, fill=TEXT_DIM,
                          font=FONT_UI, anchor="center")
        c.after(50, _draw)

    def _tab_frame(self, parent):
        f = tk.Frame(parent, bg=BG)
        return f

    def _logw(self, parent, fg=None):
        w = scrolledtext.ScrolledText(
            parent, bg=BG, fg=fg or TEXT_DIM,
            font=FONT_MONO, bd=0, wrap=tk.WORD,
            insertbackground=TEXT, relief=tk.FLAT)
        w.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        w.configure(state=tk.DISABLED)
        w.tag_config("ts",      foreground=TEXT_DIM)
        w.tag_config("exec",    foreground=GREEN)
        w.tag_config("open",    foreground=ACCENT)
        w.tag_config("alert",   foreground=RED,    font=(*FONT_MONO[:2], "bold"))
        w.tag_config("warn",    foreground=YELLOW)
        w.tag_config("info",    foreground=TEXT)
        w.tag_config("dim",     foreground=TEXT_DIM)
        w.tag_config("heading", foreground=ACCENT, font=(*FONT_MONO[:2], "bold"))
        return w

    def _btn(self, parent, text, color, cmd, state=tk.NORMAL, pad=8):
        return tk.Button(parent, text=text, bg=PANEL, fg=color,
                         activebackground=BORDER, activeforeground=color,
                         font=FONT_UI, bd=0, pady=pad, cursor="hand2",
                         command=cmd, state=state, relief=tk.FLAT,
                         highlightthickness=1, highlightbackground=BORDER)

    def _section(self, parent, title):
        tk.Label(parent, text=title, bg=BG, fg=TEXT_DIM,
                 font=FONT_TINY).pack(anchor="w", pady=(8, 4))

    def _stat_row(self, parent, label_text, var):
        row = tk.Frame(parent, bg=BG)
        row.pack(fill=tk.X, pady=1)
        tk.Label(row, text=label_text, bg=BG, fg=TEXT_DIM, font=FONT_UI).pack(side=tk.LEFT)
        tk.Label(row, textvariable=var, bg=BG, fg=ACCENT,
                 font=(*FONT_UI[:2], "bold")).pack(side=tk.RIGHT)

    def _log(self, widget, text, tag="info"):
        def _a():
            widget.configure(state=tk.NORMAL)
            widget.insert(tk.END, f"[{ts()}] ", "ts")
            widget.insert(tk.END, text + "\n", tag)
            widget.see(tk.END)
            widget.configure(state=tk.DISABLED)
        self.root.after(0, _a)

    def _log_raw(self, widget, text, tag="dim"):
        def _a():
            widget.configure(state=tk.NORMAL)
            widget.insert(tk.END, text + "\n", tag)
            widget.see(tk.END)
            widget.configure(state=tk.DISABLED)
        self.root.after(0, _a)

    def _clear_log(self, widget):
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.configure(state=tk.DISABLED)

    def _set_status(self, text, color):
        def _d():
            self._status_text.set(text)
            self._status_dot.configure(fg=color)
        self.root.after(0, _d)

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


    def _start_monitor(self):
        if self._running:
            return

        if not MONITOR_BIN.exists():
            messagebox.showerror("Binary not found",
                f"'{MONITOR_BIN}' not found.\nRun 'make' in the K-Guard directory first.")
            return

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
            # C monitor binary — stdout (JSON events) piped to graphengine
            self._monitor_proc = subprocess.Popen(
                [str(MONITOR_BIN)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            #graphengine.py reads JSON from stdin, writes progress to stdout
            self._engine_proc = subprocess.Popen(
                [sys.executable, "-u", str(GRAPH_ENGINE)],
                stdin=self._monitor_proc.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, bufsize=1,
            )
            self._monitor_proc.stdout.close()

        except Exception as e:
            self._log(self._event_log, f"Failed to start: {e}", "alert")
            self._running = False
            self._set_status("Error", RED)
            return

        threading.Thread(target=self._read_engine_stdout, daemon=True).start()
        threading.Thread(target=self._read_engine_stderr, daemon=True).start()
        # Thread: stream monitor stderr → Live Events tab (kernel debug lines)
        threading.Thread(target=self._read_monitor_stderr, daemon=True).start()
       
        self._event_count_thread_active = True

    def _read_engine_stdout(self):
        """Read graphengine stdout — parse stats, route to Graph Engine tab."""
        for line in self._engine_proc.stdout:
            line = line.rstrip()
            if not line:
                continue

            # Parse node/edge counts from periodic refresh lines
            if "Nodes," in line and "Edges" in line:
                # e.g. "[LIVE REFRESH] Graph updated: 42 Nodes, 17 Edges mapped."
                try:
                    parts = line.split(":")[-1].split(",")
                    nodes = int(parts[0].strip().split()[0])
                    edges = int(parts[1].strip().split()[0])
                    self.root.after(0, lambda n=nodes, e=edges: (
                        self._node_count.set(n), self._edge_count.set(e)))
                except (ValueError, IndexError):
                    pass

            # Classify and colour-code
            if "GRAPH ADD" in line or "LIVE REFRESH" in line:
                self._log_raw(self._graph_log, line, "info")
            elif "ERROR" in line or "error" in line.lower():
                self._log_raw(self._graph_log, line, "alert")
            else:
                self._log_raw(self._graph_log, line, "dim")

        self._log(self._graph_log, "Graph engine stdout closed.", "warn")

    def _read_engine_stderr(self):
        """Read graphengine stderr (import errors, tracebacks) → Graph Engine tab."""
        for line in self._engine_proc.stderr:
            line = line.rstrip()
            if line:
                self._log_raw(self._graph_log, f"[ERR] {line}", "alert")

    def _read_monitor_stderr(self):
        """Read monitor binary stderr → Live Events tab.
        This is where the C binary prints its status / BPF debug messages.
        The JSON event stream goes to graphengine via stdout pipe."""
        for raw in self._monitor_proc.stderr:
            line = raw.decode(errors="replace").rstrip()
            if not line:
                continue

            # Count events — monitor typically prints one line per event
            self.root.after(0, lambda: self._event_count.set(self._event_count.get() + 1))

            # Simple colour routing
            low = line.lower()
            if "execve" in low or "exec" in low:
                tag = "exec"
            elif "open" in low or "file" in low:
                tag = "open"
            elif "error" in low or "failed" in low:
                tag = "alert"
            else:
                tag = "dim"
            self._log_raw(self._event_log, line, tag)

    def _stop_monitor(self):
        if not self._running:
            return

        self._log(self._event_log, "Stopping monitor — saving graph...", "warn")
        self._log(self._graph_log, "Sending SIGINT to graph engine → triggers GEXF save...", "warn")

        # SIGINT to graphengine → KeyboardInterrupt → saves GEXF
        if self._engine_proc and self._engine_proc.poll() is None:
            try:
                self._engine_proc.send_signal(signal.SIGINT)
            except ProcessLookupError:
                pass

        if self._monitor_proc and self._monitor_proc.poll() is None:
            try:
                self._monitor_proc.terminate()
            except ProcessLookupError:
                pass

        self._running = False
        self._set_status("Idle", TEXT_DIM)
        self._btn_start.configure(state=tk.NORMAL)
        self._btn_stop.configure(state=tk.DISABLED)

        self.root.after(1500, self._refresh_gexf_label)
        self._log(self._event_log, "Monitor stopped. Graph saved to system_behavior_graph.gexf", "info")
        self._log(self._graph_log, "Run Stage 2 (ML Detector) or Stage 3 (Render Graph) next.", "info")

    # ML Detector 

    def _run_ml(self):
        if not GEXF_FILE.exists():
            messagebox.showwarning("No graph data",
                f"'{GEXF_FILE.name}' not found.\n"
                "Run Stage 1 first to capture events and build the graph.")
            return

        self._clear_log(self._ml_log)
        self._log(self._ml_log, "Running Isolation Forest anomaly detector...", "heading")
        self._btn_ml.configure(state=tk.DISABLED, text="⚙  Running…")
        self._set_status("Analyzing", ACCENT)

        def _run():
            try:
                result = subprocess.run(
                    [sys.executable, str(ML_DETECTOR)],
                    cwd=str(KGUARD_DIR),
                    capture_output=True, text=True, timeout=120
                )
                output = result.stdout + (result.stderr or "")
                alert_count = 0

                if result.returncode != 0 and not output.strip():
                    self.root.after(0, lambda: self._log(
                        self._ml_log,
                        f"ML detector exited with code {result.returncode}. "
                        "Check that networkx/sklearn/numpy are installed.", "alert"))
                    return

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
                    elif line.strip():
                        self._log_raw(self._ml_log, line, "info")

                self.root.after(0, lambda: self._alert_count.set(alert_count))

                if alert_count == 0:
                    self._log(self._ml_log, "✓ No anomalies detected.", "info")
                else:
                    self._log(self._ml_log,
                              f"⚠  {alert_count} anomal{'y' if alert_count==1 else 'ies'} flagged.",
                              "alert")

            except subprocess.TimeoutExpired:
                self._log(self._ml_log, "ML detector timed out (>120s).", "alert")
            except Exception as e:
                self._log(self._ml_log, f"Error running detector: {e}", "alert")
            finally:
                self.root.after(0, lambda: self._btn_ml.configure(
                    state=tk.NORMAL, text="⚙  Run ML Detector"))
                self.root.after(0, lambda: self._set_status("Idle", TEXT_DIM))

        threading.Thread(target=_run, daemon=True).start()

        # Switch to ML Report tab automatically
        self.root.after(100, lambda: self._nb.select(2))

    # Render Graph 
    def _render_graph(self):
        if not GEXF_FILE.exists():
            messagebox.showwarning("No graph data",
                "Run Stage 1 first to generate graph data.")
            return

        self._set_status("Rendering…", YELLOW)
        self._btn_render.configure(state=tk.DISABLED, text="🗺  Rendering…")
        self._draw_graph_placeholder("Rendering interactive graph, please wait…")

        def _run():
            try:
                result = subprocess.run(
                    [sys.executable, str(VIEW_GRAPH)],
                    cwd=str(KGUARD_DIR),
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0 and HTML_FILE.exists():
                    self.root.after(0, self._on_render_success)
                else:
                    err = result.stderr or result.stdout or "Unknown error"
                    self.root.after(0, lambda: messagebox.showerror("Render failed", err))
                    self.root.after(0, lambda: self._set_status("Error", RED))
                    self.root.after(0, lambda: self._draw_graph_placeholder(
                        f"Render failed: {err[:120]}"))
            except subprocess.TimeoutExpired:
                self.root.after(0, lambda: messagebox.showerror(
                    "Timeout", "Graph render timed out."))
            except Exception as e:
                self.root.after(0, lambda: self._open_in_browser())
            finally:
                self.root.after(0, lambda: self._btn_render.configure(
                    state=tk.NORMAL, text="🗺  Render Graph"))

        threading.Thread(target=_run, daemon=True).start()

    def _on_render_success(self):
        self._set_status("Idle", TEXT_DIM)
        mtime = datetime.fromtimestamp(HTML_FILE.stat().st_mtime).strftime("%H:%M:%S")
        self._graph_info.configure(
            text=f"kguard_interactive_graph.html  —  saved {mtime}")
        self._draw_graph_placeholder(f"✓ Graph rendered — click 🌐 Open in Browser to view")
        self._open_in_browser()
        self._nb.select(3)

    
    def _refresh_graph_view(self):
        """Re-render then update the info label."""
        self._render_graph()

    def _open_in_browser(self):
        if not HTML_FILE.exists():
            messagebox.showwarning("No graph file",
                "Render the graph first (Stage 3).")
            return
        user = os.environ.get("SUDO_USER", "root")
        uid = subprocess.check_output(["id", "-u", user]).decode().strip()
        env = {
            "DISPLAY": os.environ.get("DISPLAY", ":0"),
            "WAYLAND_DISPLAY": os.environ.get("WAYLAND_DISPLAY", "wayland-0"),
            "XDG_RUNTIME_DIR": f"/run/user/{uid}",
            "HOME": f"/home/{user}",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }
        for browser in ("firefox", "chromium", "chromium-browser", "google-chrome", "xdg-open"):
            try:
                subprocess.Popen(
                    ["sudo", "-u", user,
                    f"DISPLAY={env['DISPLAY']}",
                    f"WAYLAND_DISPLAY={env['WAYLAND_DISPLAY']}",
                    f"XDG_RUNTIME_DIR={env['XDG_RUNTIME_DIR']}",
                    f"HOME={env['HOME']}",
                    browser, str(HTML_FILE)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                return
            except FileNotFoundError:
                continue


    def _on_close(self):
        if self._running:
            if messagebox.askyesno("Quit", "Monitor is running. Stop it and quit?"):
                self._stop_monitor()
                self.root.after(900, self.root.destroy)
        else:
            self.root.destroy()


if __name__ == "__main__":
    try:
        from PIL import Image, ImageTk  
    except ImportError:
        pass  

    root = tk.Tk()
    app  = KGuardGUI(root)
    root.mainloop()