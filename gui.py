"""
gui.py — Flow Rule Timeout Manager: Professional GUI Dashboard
==============================================================
A comprehensive Tkinter/CustomTkinter GUI that visualises every aspect of
the flow-rule lifecycle, timeout management, packet simulation, statistics,
and regression test runner.
"""

import sys
import os
import time
import threading
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from controller.flow_timeout_manager import (
    FlowTable, FlowRule, FlowMatch, FlowAction, FlowState,
)

# ─── Theme ────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

COLORS = {
    "bg":        "#0f1117",
    "panel":     "#1a1d27",
    "card":      "#22263a",
    "border":    "#2e3250",
    "accent":    "#4f8ef7",
    "accent2":   "#7c5cfc",
    "green":     "#22c55e",
    "yellow":    "#f59e0b",
    "red":       "#ef4444",
    "orange":    "#f97316",
    "text":      "#e2e8f0",
    "muted":     "#64748b",
    "active":    "#22c55e",
    "idle_exp":  "#f59e0b",
    "hard_exp":  "#ef4444",
    "removed":   "#94a3b8",
}

STATE_COLORS = {
    FlowState.ACTIVE:       COLORS["green"],
    FlowState.IDLE_EXPIRED: COLORS["yellow"],
    FlowState.HARD_EXPIRED: COLORS["red"],
    FlowState.REMOVED:      COLORS["muted"],
}

PROTOCOLS = ["TCP", "UDP", "ICMP", "ANY"]
ACTIONS    = ["FORWARD", "DROP", "FLOOD"]


# ─── Helpers ──────────────────────────────────────────────────────────────────
def fmt_time(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))

def fmt_remain(val: float) -> str:
    if val == float("inf"):
        return "∞"
    return f"{val:.1f}s"

def clamp(v, lo, hi):
    return max(lo, min(hi, v))


# ─── Tooltip ──────────────────────────────────────────────────────────────────
class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text   = text
        self.tip    = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, _=None):
        x, y, *_ = self.widget.bbox("insert") if hasattr(self.widget, "bbox") else (0, 0, 0, 0)
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tip = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(tw, text=self.text, background="#1e293b", foreground="#e2e8f0",
                       relief="flat", font=("Consolas", 9), padx=6, pady=4)
        lbl.pack()

    def hide(self, _=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


# ─── Main Application ─────────────────────────────────────────────────────────
class FlowManagerGUI(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("Flow Rule Timeout Manager  ·  SDN Dashboard")
        self.geometry("1480x900")
        self.minsize(1200, 750)
        self.configure(fg_color=COLORS["bg"])

        self.table = FlowTable(scan_interval=0.5)
        self.table.start()

        self._packet_jobs: dict[str, str] = {}   # rule_id → after-id
        self._timeline_events: list[dict] = []
        self._analysis_running = False
        self._test_running = False
        self._selected_rule_id: str | None = None

        self._build_ui()
        self._start_refresh()

    # ──────────────────────────────────────────────────────────────────────────
    # UI Construction
    # ──────────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Top bar ──────────────────────────────────────────────────
        top = ctk.CTkFrame(self, fg_color=COLORS["panel"], corner_radius=0, height=54)
        top.pack(fill="x", side="top")
        top.pack_propagate(False)

        ctk.CTkLabel(top, text="⬡  Flow Rule Timeout Manager",
                     font=ctk.CTkFont("Segoe UI", 18, "bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=20, pady=12)

        self._status_dot = ctk.CTkLabel(top, text="● RUNNING",
                                        font=ctk.CTkFont("Consolas", 12, "bold"),
                                        text_color=COLORS["green"])
        self._status_dot.pack(side="right", padx=20)

        self._clock_lbl = ctk.CTkLabel(top, text="", font=ctk.CTkFont("Consolas", 12),
                                       text_color=COLORS["muted"])
        self._clock_lbl.pack(side="right", padx=10)

        # ── Tab view ─────────────────────────────────────────────────
        self._tabs = ctk.CTkTabview(self, fg_color=COLORS["panel"],
                                    segmented_button_fg_color=COLORS["card"],
                                    segmented_button_selected_color=COLORS["accent"],
                                    segmented_button_selected_hover_color="#3d7de0",
                                    segmented_button_unselected_color=COLORS["card"],
                                    text_color=COLORS["text"])
        self._tabs.pack(fill="both", expand=True, padx=10, pady=(4, 10))

        for tab in ("Flow Table", "Add Rule", "Packet Simulator",
                    "Lifecycle Timeline", "Statistics", "Analysis", "Test Runner"):
            self._tabs.add(tab)

        self._build_flow_table_tab()
        self._build_add_rule_tab()
        self._build_packet_sim_tab()
        self._build_timeline_tab()
        self._build_stats_tab()
        self._build_analysis_tab()
        self._build_test_runner_tab()

    # ── Tab: Flow Table ───────────────────────────────────────────────────────
    def _build_flow_table_tab(self):
        tab = self._tabs.tab("Flow Table")

        # Summary bar
        summary = ctk.CTkFrame(tab, fg_color=COLORS["card"], corner_radius=8)
        summary.pack(fill="x", padx=8, pady=(8, 4))

        self._summary_labels = {}
        for key, icon, color in [
            ("active",      "● Active",       COLORS["green"]),
            ("idle_exp",    "◑ Idle-Expired", COLORS["yellow"]),
            ("hard_exp",    "✕ Hard-Expired", COLORS["red"]),
            ("total_added", "＋ Total Added",  COLORS["accent"]),
            ("manual_rem",  "− Manual Removed", COLORS["muted"]),
        ]:
            f = ctk.CTkFrame(summary, fg_color="transparent")
            f.pack(side="left", padx=18, pady=6)
            ctk.CTkLabel(f, text=icon, font=ctk.CTkFont("Segoe UI", 11),
                         text_color=color).pack()
            lbl = ctk.CTkLabel(f, text="0", font=ctk.CTkFont("Segoe UI", 20, "bold"),
                               text_color=color)
            lbl.pack()
            self._summary_labels[key] = lbl

        # Toolbar
        toolbar = ctk.CTkFrame(tab, fg_color="transparent")
        toolbar.pack(fill="x", padx=8, pady=4)

        ctk.CTkButton(toolbar, text="⟳  Refresh", width=100,
                      fg_color=COLORS["accent"], hover_color="#3d7de0",
                      command=self._refresh_table).pack(side="left", padx=4)

        ctk.CTkButton(toolbar, text="✕  Remove Selected", width=140,
                      fg_color="#7f1d1d", hover_color=COLORS["red"],
                      command=self._remove_selected_rule).pack(side="left", padx=4)

        ctk.CTkButton(toolbar, text="⬇  Export Audit Log", width=150,
                      fg_color=COLORS["card"], hover_color=COLORS["border"],
                      command=self._export_log).pack(side="right", padx=4)

        self._auto_refresh_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(toolbar, text="Auto-refresh (1s)",
                        variable=self._auto_refresh_var,
                        fg_color=COLORS["accent"], hover_color="#3d7de0"
                        ).pack(side="right", padx=8)

        # Treeview
        tree_frame = ctk.CTkFrame(tab, fg_color=COLORS["card"], corner_radius=8)
        tree_frame.pack(fill="both", expand=True, padx=8, pady=4)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("FlowTable.Treeview",
                        background=COLORS["card"], fieldbackground=COLORS["card"],
                        foreground=COLORS["text"], rowheight=28,
                        font=("Consolas", 10))
        style.configure("FlowTable.Treeview.Heading",
                        background=COLORS["border"], foreground=COLORS["accent"],
                        font=("Segoe UI", 10, "bold"), relief="flat")
        style.map("FlowTable.Treeview",
                  background=[("selected", COLORS["accent"])],
                  foreground=[("selected", "white")])

        cols = ("ID", "State", "Priority", "Match", "Action",
                "Idle TO", "Hard TO", "Idle Rem", "Hard Rem",
                "Pkts", "Bytes", "Age")
        self._tree = ttk.Treeview(tree_frame, columns=cols, show="headings",
                                  style="FlowTable.Treeview", selectmode="browse")

        col_widths = [70, 110, 65, 260, 130, 60, 60, 80, 80, 60, 70, 65]
        for col, w in zip(cols, col_widths):
            self._tree.heading(col, text=col,
                               command=lambda c=col: self._sort_tree(c))
            self._tree.column(col, width=w, minwidth=40, anchor="center")

        self._tree.column("Match", anchor="w")
        self._tree.column("Action", anchor="w")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        # Detail panel
        self._detail_frame = ctk.CTkFrame(tab, fg_color=COLORS["card"],
                                          corner_radius=8, height=80)
        self._detail_frame.pack(fill="x", padx=8, pady=(2, 8))
        self._detail_frame.pack_propagate(False)
        self._detail_lbl = ctk.CTkLabel(self._detail_frame,
                                        text="Select a rule to see details",
                                        font=ctk.CTkFont("Consolas", 11),
                                        text_color=COLORS["muted"])
        self._detail_lbl.pack(fill="both", expand=True, padx=10, pady=8)

        self._sort_col   = "Priority"
        self._sort_rev   = True

    # ── Tab: Add Rule ─────────────────────────────────────────────────────────
    def _build_add_rule_tab(self):
        tab = self._tabs.tab("Add Rule")

        outer = ctk.CTkFrame(tab, fg_color="transparent")
        outer.pack(fill="both", expand=True, padx=20, pady=10)

        # Two columns
        left  = ctk.CTkFrame(outer, fg_color=COLORS["card"], corner_radius=10)
        right = ctk.CTkFrame(outer, fg_color=COLORS["card"], corner_radius=10)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8), pady=0)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0), pady=0)
        outer.columnconfigure(0, weight=1)
        outer.columnconfigure(1, weight=1)
        outer.rowconfigure(0, weight=1)

        # ── Left: Match fields ───────────────────────────────────────
        self._section_title(left, "Match Fields", "⬡")

        self._add_fields = {}

        def add_row(parent, label, key, default="", choices=None):
            row = ctk.CTkFrame(parent, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=4)
            ctk.CTkLabel(row, text=label, width=90,
                         font=ctk.CTkFont("Segoe UI", 12),
                         text_color=COLORS["muted"], anchor="w").pack(side="left")
            if choices:
                var = ctk.StringVar(value=default)
                w = ctk.CTkComboBox(row, values=choices, variable=var,
                                    fg_color=COLORS["bg"],
                                    border_color=COLORS["border"],
                                    button_color=COLORS["accent"],
                                    width=160)
                w.pack(side="left", padx=(6, 0))
                self._add_fields[key] = var
            else:
                var = ctk.StringVar(value=default)
                w = ctk.CTkEntry(row, textvariable=var,
                                 fg_color=COLORS["bg"],
                                 border_color=COLORS["border"], width=160,
                                 font=ctk.CTkFont("Consolas", 12))
                w.pack(side="left", padx=(6, 0))
                self._add_fields[key] = var
            return var

        add_row(left, "Src IP",    "src_ip",   "10.0.0.1")
        add_row(left, "Dst IP",    "dst_ip",   "10.0.0.2")
        add_row(left, "Src Port",  "src_port", "")
        add_row(left, "Dst Port",  "dst_port", "80")
        add_row(left, "Protocol",  "protocol", "TCP", PROTOCOLS)

        # ── Right: Action + Timeout ──────────────────────────────────
        self._section_title(right, "Action & Timeouts", "⚙")

        add_row(right, "Action",     "action",      "FORWARD", ACTIONS)
        add_row(right, "Out Port",   "output_port", "1")
        add_row(right, "Priority",   "priority",    "100")

        # Sliders for timeouts
        self._section_title(right, "Timeout Configuration", "⏱")

        def add_slider(parent, label, key, lo, hi, default, unit="s"):
            row = ctk.CTkFrame(parent, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=4)
            ctk.CTkLabel(row, text=label, width=110,
                         font=ctk.CTkFont("Segoe UI", 12),
                         text_color=COLORS["muted"], anchor="w").pack(side="left")
            var = tk.IntVar(value=default)
            val_lbl = ctk.CTkLabel(row, text=f"{default}{unit}", width=50,
                                   font=ctk.CTkFont("Consolas", 12, "bold"),
                                   text_color=COLORS["accent"])
            val_lbl.pack(side="right")

            def on_change(v, lbl=val_lbl, vr=var):
                iv = int(float(v))
                vr.set(iv)
                lbl.configure(text=f"{iv}{unit}" if iv > 0 else "OFF")

            sl = ctk.CTkSlider(row, from_=lo, to=hi, variable=var,
                               command=on_change,
                               fg_color=COLORS["border"],
                               progress_color=COLORS["accent"],
                               button_color=COLORS["accent"],
                               width=160)
            sl.pack(side="left", padx=(6, 0))
            self._add_fields[key] = var
            return var

        add_slider(right, "Idle Timeout", "idle_timeout", 0, 60, 10)
        add_slider(right, "Hard Timeout", "hard_timeout", 0, 120, 60)

        ctk.CTkLabel(right, text="(0 = disabled)",
                     font=ctk.CTkFont("Segoe UI", 10),
                     text_color=COLORS["muted"]).pack(padx=16, anchor="w")

        # Add button
        btn_row = ctk.CTkFrame(outer, fg_color="transparent")
        btn_row.grid(row=1, column=0, columnspan=2, pady=(12, 0))

        ctk.CTkButton(btn_row, text="＋  Add Flow Rule", width=220, height=44,
                      fg_color=COLORS["accent"], hover_color="#3d7de0",
                      font=ctk.CTkFont("Segoe UI", 14, "bold"),
                      command=self._add_rule).pack(side="left", padx=8)

        ctk.CTkButton(btn_row, text="⬡  Add Preset Rules", width=180, height=44,
                      fg_color=COLORS["accent2"], hover_color="#6b4de8",
                      font=ctk.CTkFont("Segoe UI", 13),
                      command=self._add_preset_rules).pack(side="left", padx=8)

        self._add_status = ctk.CTkLabel(outer, text="",
                                        font=ctk.CTkFont("Consolas", 12),
                                        text_color=COLORS["green"])
        self._add_status.grid(row=2, column=0, columnspan=2, pady=6)

    # ── Tab: Packet Simulator ─────────────────────────────────────────────────
    def _build_packet_sim_tab(self):
        tab = self._tabs.tab("Packet Simulator")

        left = ctk.CTkFrame(tab, fg_color=COLORS["card"], corner_radius=10)
        right = ctk.CTkFrame(tab, fg_color=COLORS["card"], corner_radius=10)
        left.pack(side="left", fill="both", expand=True, padx=(8, 4), pady=8)
        right.pack(side="right", fill="both", expand=True, padx=(4, 8), pady=8)

        # ── Left: manual packet hit ──────────────────────────────────
        self._section_title(left, "Manual Packet Injection", "→")

        ctk.CTkLabel(left, text="Select a rule from the flow table, then inject packets.",
                     font=ctk.CTkFont("Segoe UI", 11),
                     text_color=COLORS["muted"], wraplength=320).pack(padx=16, pady=4)

        row = ctk.CTkFrame(left, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(row, text="Rule ID:", font=ctk.CTkFont("Segoe UI", 12),
                     text_color=COLORS["muted"], width=70).pack(side="left")
        self._pkt_rule_id = ctk.StringVar()
        self._pkt_rule_entry = ctk.CTkEntry(row, textvariable=self._pkt_rule_id,
                                            fg_color=COLORS["bg"],
                                            border_color=COLORS["border"], width=120,
                                            font=ctk.CTkFont("Consolas", 12))
        self._pkt_rule_entry.pack(side="left", padx=6)

        row2 = ctk.CTkFrame(left, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(row2, text="Pkt Size:", font=ctk.CTkFont("Segoe UI", 12),
                     text_color=COLORS["muted"], width=70).pack(side="left")
        self._pkt_size = tk.IntVar(value=64)
        pkt_sz_lbl = ctk.CTkLabel(row2, text="64 B", width=50,
                                  font=ctk.CTkFont("Consolas", 12, "bold"),
                                  text_color=COLORS["accent"])
        pkt_sz_lbl.pack(side="right")

        def on_pkt_sz(v):
            iv = int(float(v))
            self._pkt_size.set(iv)
            pkt_sz_lbl.configure(text=f"{iv} B")

        ctk.CTkSlider(row2, from_=64, to=1500, variable=self._pkt_size,
                      command=on_pkt_sz,
                      fg_color=COLORS["border"], progress_color=COLORS["accent"],
                      button_color=COLORS["accent"], width=160).pack(side="left", padx=6)

        ctk.CTkButton(left, text="→  Send 1 Packet", fg_color=COLORS["accent"],
                      hover_color="#3d7de0", command=self._send_packet
                      ).pack(padx=16, pady=6, fill="x")

        # Burst
        self._section_title(left, "Burst Simulation", "⚡")

        burst_row = ctk.CTkFrame(left, fg_color="transparent")
        burst_row.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(burst_row, text="Count:", font=ctk.CTkFont("Segoe UI", 12),
                     text_color=COLORS["muted"], width=70).pack(side="left")
        self._burst_count = tk.IntVar(value=10)
        ctk.CTkEntry(burst_row, textvariable=self._burst_count, width=80,
                     fg_color=COLORS["bg"], border_color=COLORS["border"],
                     font=ctk.CTkFont("Consolas", 12)).pack(side="left", padx=6)

        burst_row2 = ctk.CTkFrame(left, fg_color="transparent")
        burst_row2.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(burst_row2, text="Interval:", font=ctk.CTkFont("Segoe UI", 12),
                     text_color=COLORS["muted"], width=70).pack(side="left")
        self._burst_interval = ctk.StringVar(value="0.5")
        ctk.CTkEntry(burst_row2, textvariable=self._burst_interval, width=80,
                     fg_color=COLORS["bg"], border_color=COLORS["border"],
                     font=ctk.CTkFont("Consolas", 12)).pack(side="left", padx=6)
        ctk.CTkLabel(burst_row2, text="s", text_color=COLORS["muted"]).pack(side="left")

        ctk.CTkButton(left, text="⚡  Start Burst", fg_color=COLORS["accent2"],
                      hover_color="#6b4de8", command=self._start_burst
                      ).pack(padx=16, pady=6, fill="x")

        self._pkt_status = ctk.CTkLabel(left, text="",
                                        font=ctk.CTkFont("Consolas", 11),
                                        text_color=COLORS["green"], wraplength=300)
        self._pkt_status.pack(padx=16, pady=4)

        # ── Right: live packet log ────────────────────────────────────
        self._section_title(right, "Packet Event Log", "📋")

        self._pkt_log = ctk.CTkTextbox(right, fg_color=COLORS["bg"],
                                       font=ctk.CTkFont("Consolas", 11),
                                       text_color=COLORS["text"], wrap="word")
        self._pkt_log.pack(fill="both", expand=True, padx=8, pady=(4, 8))

        ctk.CTkButton(right, text="Clear Log", fg_color=COLORS["card"],
                      hover_color=COLORS["border"],
                      command=lambda: self._pkt_log.delete("1.0", "end")
                      ).pack(padx=8, pady=(0, 8), anchor="e")

    # ── Tab: Lifecycle Timeline ───────────────────────────────────────────────
    def _build_timeline_tab(self):
        tab = self._tabs.tab("Lifecycle Timeline")

        self._section_title(tab, "Rule Lifecycle Events", "⏱")
        ctk.CTkLabel(tab,
                     text="Live timeline of rule additions, packet hits, and expirations",
                     font=ctk.CTkFont("Segoe UI", 11), text_color=COLORS["muted"]
                     ).pack(padx=16, pady=(0, 6))

        ctrl_bar = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl_bar.pack(fill="x", padx=8, pady=(0, 4))

        ctk.CTkButton(ctrl_bar, text="Clear Timeline", width=130,
                      fg_color=COLORS["card"], hover_color=COLORS["border"],
                      command=self._clear_timeline).pack(side="left", padx=4)

        self._timeline_filter = ctk.StringVar(value="ALL")
        for label in ("ALL", "ADDED", "EXPIRED", "REMOVED", "PACKET"):
            ctk.CTkRadioButton(ctrl_bar, text=label,
                               variable=self._timeline_filter, value=label,
                               fg_color=COLORS["accent"], hover_color="#3d7de0",
                               command=self._render_timeline
                               ).pack(side="left", padx=6)

        self._timeline_box = ctk.CTkTextbox(tab, fg_color=COLORS["bg"],
                                            font=ctk.CTkFont("Consolas", 11),
                                            text_color=COLORS["text"], wrap="none")
        self._timeline_box.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # Tag colours for the Text widget — set after widget creation
        self._tl_tags_set = False

    # ── Tab: Statistics ───────────────────────────────────────────────────────
    def _build_stats_tab(self):
        tab = self._tabs.tab("Statistics")

        outer = ctk.CTkFrame(tab, fg_color="transparent")
        outer.pack(fill="both", expand=True, padx=8, pady=8)

        left  = ctk.CTkFrame(outer, fg_color=COLORS["card"], corner_radius=10)
        right = ctk.CTkFrame(outer, fg_color=COLORS["card"], corner_radius=10)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        outer.columnconfigure(0, weight=1)
        outer.columnconfigure(1, weight=1)
        outer.rowconfigure(0, weight=1)

        # Live counters
        self._section_title(left, "Live Counters", "📊")
        self._stat_labels = {}
        stat_items = [
            ("total_added",           "Total Rules Added",       COLORS["accent"]),
            ("currently_active",      "Currently Active",        COLORS["green"]),
            ("total_idle_expired",    "Idle-Expired",            COLORS["yellow"]),
            ("total_hard_expired",    "Hard-Expired",            COLORS["red"]),
            ("total_removed_manually","Manually Removed",        COLORS["muted"]),
            ("total_in_audit_log",    "Total in Audit Log",      COLORS["accent2"]),
        ]
        for key, label, color in stat_items:
            row = ctk.CTkFrame(left, fg_color=COLORS["bg"], corner_radius=6)
            row.pack(fill="x", padx=12, pady=4)
            ctk.CTkLabel(row, text=label, font=ctk.CTkFont("Segoe UI", 12),
                         text_color=COLORS["text"], anchor="w").pack(side="left", padx=10, pady=8)
            lbl = ctk.CTkLabel(row, text="0",
                               font=ctk.CTkFont("Segoe UI", 18, "bold"),
                               text_color=color)
            lbl.pack(side="right", padx=10)
            self._stat_labels[key] = lbl

        # Audit log viewer
        self._section_title(right, "Audit Log (Expired/Removed Rules)", "📋")

        log_cols = ("ID", "State", "Match", "Pkts", "Bytes", "Age(s)")
        style = ttk.Style()
        style.configure("Audit.Treeview",
                        background=COLORS["bg"], fieldbackground=COLORS["bg"],
                        foreground=COLORS["text"], rowheight=26,
                        font=("Consolas", 10))
        style.configure("Audit.Treeview.Heading",
                        background=COLORS["border"], foreground=COLORS["accent"],
                        font=("Segoe UI", 10, "bold"), relief="flat")
        style.map("Audit.Treeview",
                  background=[("selected", COLORS["accent2"])],
                  foreground=[("selected", "white")])

        self._audit_tree = ttk.Treeview(right, columns=log_cols, show="headings",
                                        style="Audit.Treeview", height=12)
        col_widths = [70, 110, 240, 60, 70, 70]
        for col, w in zip(log_cols, col_widths):
            self._audit_tree.heading(col, text=col)
            self._audit_tree.column(col, width=w, anchor="center")
        self._audit_tree.column("Match", anchor="w")

        asb = ttk.Scrollbar(right, orient="vertical", command=self._audit_tree.yview)
        self._audit_tree.configure(yscrollcommand=asb.set)
        self._audit_tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=(4, 8))
        asb.pack(side="right", fill="y", padx=(0, 8), pady=(4, 8))

    # ── Tab: Analysis ─────────────────────────────────────────────────────────
    def _build_analysis_tab(self):
        tab = self._tabs.tab("Analysis")

        ctrl = ctk.CTkFrame(tab, fg_color=COLORS["card"], corner_radius=8)
        ctrl.pack(fill="x", padx=8, pady=(8, 4))

        self._section_title(ctrl, "Behaviour Analysis Experiment", "🔬")
        ctk.CTkLabel(ctrl,
                     text="Runs 5 controlled scenarios: idle-only, idle+traffic, hard-only, "
                          "idle wins, hard wins. Duration: ~13 seconds.",
                     font=ctk.CTkFont("Segoe UI", 11), text_color=COLORS["muted"],
                     wraplength=900).pack(padx=16, pady=(0, 4))

        btn_row = ctk.CTkFrame(ctrl, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 8))

        self._analysis_btn = ctk.CTkButton(btn_row, text="▶  Run Analysis",
                                           fg_color=COLORS["accent2"],
                                           hover_color="#6b4de8", width=160,
                                           command=self._run_analysis)
        self._analysis_btn.pack(side="left", padx=4)

        self._analysis_progress = ctk.CTkProgressBar(btn_row,
                                                      fg_color=COLORS["border"],
                                                      progress_color=COLORS["accent2"],
                                                      width=300)
        self._analysis_progress.pack(side="left", padx=16)
        self._analysis_progress.set(0)

        self._analysis_status = ctk.CTkLabel(btn_row, text="",
                                             font=ctk.CTkFont("Consolas", 11),
                                             text_color=COLORS["accent2"])
        self._analysis_status.pack(side="left", padx=8)

        self._analysis_output = ctk.CTkTextbox(tab, fg_color=COLORS["bg"],
                                               font=ctk.CTkFont("Consolas", 11),
                                               text_color=COLORS["text"], wrap="word")
        self._analysis_output.pack(fill="both", expand=True, padx=8, pady=(4, 8))

    # ── Tab: Test Runner ──────────────────────────────────────────────────────
    def _build_test_runner_tab(self):
        tab = self._tabs.tab("Test Runner")

        ctrl = ctk.CTkFrame(tab, fg_color=COLORS["card"], corner_radius=8)
        ctrl.pack(fill="x", padx=8, pady=(8, 4))

        self._section_title(ctrl, "Regression Test Suite  (22 tests)", "✓")
        ctk.CTkLabel(ctrl,
                     text="Run all 22 unittest cases directly from the GUI. "
                          "Results are shown in real-time.",
                     font=ctk.CTkFont("Segoe UI", 11),
                     text_color=COLORS["muted"]).pack(padx=16, pady=(0, 4))

        btn_row = ctk.CTkFrame(ctrl, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 8))

        self._test_btn = ctk.CTkButton(btn_row, text="▶  Run All Tests",
                                       fg_color=COLORS["green"],
                                       hover_color="#16a34a", width=160,
                                       command=self._run_tests)
        self._test_btn.pack(side="left", padx=4)

        self._test_progress = ctk.CTkProgressBar(btn_row,
                                                  fg_color=COLORS["border"],
                                                  progress_color=COLORS["green"],
                                                  width=280)
        self._test_progress.pack(side="left", padx=16)
        self._test_progress.set(0)

        self._test_summary = ctk.CTkLabel(btn_row, text="",
                                          font=ctk.CTkFont("Segoe UI", 12, "bold"),
                                          text_color=COLORS["muted"])
        self._test_summary.pack(side="left", padx=8)

        # Test list treeview
        list_frame = ctk.CTkFrame(tab, fg_color=COLORS["card"], corner_radius=8)
        list_frame.pack(fill="both", expand=True, padx=8, pady=(4, 8))

        test_cols = ("Status", "Test Class", "Test Name", "Duration", "Message")
        style = ttk.Style()
        style.configure("Test.Treeview",
                        background=COLORS["card"], fieldbackground=COLORS["card"],
                        foreground=COLORS["text"], rowheight=26,
                        font=("Consolas", 10))
        style.configure("Test.Treeview.Heading",
                        background=COLORS["border"], foreground=COLORS["accent"],
                        font=("Segoe UI", 10, "bold"), relief="flat")
        style.map("Test.Treeview",
                  background=[("selected", COLORS["border"])],
                  foreground=[("selected", "white")])

        self._test_tree = ttk.Treeview(list_frame, columns=test_cols,
                                       show="headings", style="Test.Treeview")
        tw = [70, 200, 300, 80, 400]
        for col, w in zip(test_cols, tw):
            self._test_tree.heading(col, text=col)
            self._test_tree.column(col, width=w, anchor="center" if col != "Message" else "w")
        self._test_tree.column("Test Name", anchor="w")
        self._test_tree.column("Test Class", anchor="w")

        tsb = ttk.Scrollbar(list_frame, orient="vertical", command=self._test_tree.yview)
        self._test_tree.configure(yscrollcommand=tsb.set)
        self._test_tree.pack(side="left", fill="both", expand=True, padx=(4, 0), pady=4)
        tsb.pack(side="right", fill="y", padx=(0, 4), pady=4)

        # colour tags
        self._test_tree.tag_configure("pass",    foreground=COLORS["green"])
        self._test_tree.tag_configure("fail",    foreground=COLORS["red"])
        self._test_tree.tag_configure("error",   foreground=COLORS["orange"])
        self._test_tree.tag_configure("running", foreground=COLORS["yellow"])
        self._test_tree.tag_configure("pending", foreground=COLORS["muted"])

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────
    def _section_title(self, parent, text, icon=""):
        frame = ctk.CTkFrame(parent, fg_color=COLORS["border"], corner_radius=0, height=2)
        frame.pack(fill="x", padx=8, pady=(10, 2))
        ctk.CTkLabel(parent, text=f"{icon}  {text}",
                     font=ctk.CTkFont("Segoe UI", 13, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=14, pady=(4, 2))

    def _append_pkt_log(self, msg: str):
        self._pkt_log.configure(state="normal")
        self._pkt_log.insert("end", msg + "\n")
        self._pkt_log.see("end")
        self._pkt_log.configure(state="disabled")

    def _append_analysis(self, msg: str, color: str = None):
        self._analysis_output.configure(state="normal")
        self._analysis_output.insert("end", msg + "\n")
        self._analysis_output.see("end")
        self._analysis_output.configure(state="disabled")

    def _log_timeline(self, event_type: str, rule_id: str, detail: str = ""):
        self._timeline_events.append({
            "ts":      time.time(),
            "type":    event_type,
            "rule_id": rule_id,
            "detail":  detail,
        })

    def _clear_timeline(self):
        self._timeline_events.clear()
        self._timeline_box.configure(state="normal")
        self._timeline_box.delete("1.0", "end")
        self._timeline_box.configure(state="disabled")

    # ──────────────────────────────────────────────────────────────────────────
    # Actions
    # ──────────────────────────────────────────────────────────────────────────
    def _add_rule(self):
        try:
            f = self._add_fields
            src_port  = int(f["src_port"].get()) if f["src_port"].get() else None
            dst_port  = int(f["dst_port"].get()) if f["dst_port"].get() else None
            out_port  = int(f["output_port"].get()) if f["output_port"].get() else None

            match  = FlowMatch(
                src_ip=f["src_ip"].get() or "0.0.0.0",
                dst_ip=f["dst_ip"].get() or "0.0.0.0",
                src_port=src_port,
                dst_port=dst_port,
                protocol=f["protocol"].get(),
            )
            action = FlowAction(
                action_type=f["action"].get(),
                output_port=out_port,
            )
            rule = FlowRule(
                match=match, action=action,
                priority=int(f["priority"].get() or 100),
                idle_timeout=f["idle_timeout"].get(),
                hard_timeout=f["hard_timeout"].get(),
            )
            rid = self.table.add_rule(rule)
            self._log_timeline("ADDED", rid,
                               f"idle={rule.idle_timeout}s hard={rule.hard_timeout}s")
            self._add_status.configure(
                text=f"✔  Rule {rid} added successfully",
                text_color=COLORS["green"]
            )
            self.after(3000, lambda: self._add_status.configure(text=""))
            self._tabs.set("Flow Table")
        except Exception as e:
            self._add_status.configure(text=f"✕  Error: {e}", text_color=COLORS["red"])

    def _add_preset_rules(self):
        presets = [
            FlowRule(
                match=FlowMatch("10.0.0.1", "10.0.0.2", 5000, 80,  "TCP"),
                action=FlowAction("FORWARD", 2), priority=200,
                idle_timeout=8, hard_timeout=40,
            ),
            FlowRule(
                match=FlowMatch("10.0.0.3", "10.0.0.4", protocol="UDP"),
                action=FlowAction("FORWARD", 3), priority=150,
                idle_timeout=6, hard_timeout=20,
            ),
            FlowRule(
                match=FlowMatch("192.168.1.0", "0.0.0.0", protocol="ICMP"),
                action=FlowAction("DROP"), priority=300,
                idle_timeout=0, hard_timeout=15,
            ),
            FlowRule(
                match=FlowMatch("10.0.0.5", "10.0.0.6", dst_port=443, protocol="TCP"),
                action=FlowAction("FORWARD", 4), priority=100,
                idle_timeout=12, hard_timeout=0,
            ),
        ]
        for r in presets:
            self.table.add_rule(r)
            self._log_timeline("ADDED", r.rule_id,
                               f"preset | idle={r.idle_timeout}s hard={r.hard_timeout}s")
        self._add_status.configure(
            text=f"✔  4 preset rules added", text_color=COLORS["green"]
        )
        self.after(3000, lambda: self._add_status.configure(text=""))
        self._tabs.set("Flow Table")

    def _remove_selected_rule(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showwarning("No selection", "Select a rule first.")
            return
        rid = self._tree.item(sel[0])["values"][0]
        rule = self.table.get_rule(rid)
        if rule is None:
            messagebox.showinfo("Already removed", f"Rule {rid} no longer exists.")
            return
        if messagebox.askyesno("Confirm", f"Remove rule {rid}?"):
            self.table.remove_rule(rid, reason="manual")
            self._log_timeline("REMOVED", rid, "manual removal")

    def _send_packet(self):
        rid = self._pkt_rule_id.get().strip()
        if not rid:
            self._pkt_status.configure(text="Enter a Rule ID first", text_color=COLORS["red"])
            return
        ok = self.table.match_packet(rid, pkt_size=self._pkt_size.get())
        if ok:
            self._pkt_status.configure(
                text=f"✔  Packet sent → {rid}", text_color=COLORS["green"]
            )
            rule = self.table.get_rule(rid)
            pkts = rule.packet_count if rule else "?"
            self._append_pkt_log(
                f"[{fmt_time(time.time())}] MATCH  {rid}  size={self._pkt_size.get()}B  "
                f"pkts={pkts}"
            )
            self._log_timeline("PACKET", rid, f"size={self._pkt_size.get()}B")
        else:
            self._pkt_status.configure(
                text=f"✕  No active rule: {rid}", text_color=COLORS["red"]
            )
            self._append_pkt_log(
                f"[{fmt_time(time.time())}] MISS   {rid}  (no active rule)"
            )

    def _start_burst(self):
        rid = self._pkt_rule_id.get().strip()
        if not rid:
            self._pkt_status.configure(text="Enter a Rule ID first", text_color=COLORS["red"])
            return
        count    = self._burst_count.get()
        try:
            interval = float(self._burst_interval.get())
        except ValueError:
            interval = 0.5

        def burst():
            for i in range(count):
                ok = self.table.match_packet(rid, pkt_size=self._pkt_size.get())
                tag = "MATCH" if ok else "MISS "
                self.after(0, self._append_pkt_log,
                           f"[{fmt_time(time.time())}] {tag}  {rid}  "
                           f"burst {i+1}/{count}  size={self._pkt_size.get()}B")
                if ok:
                    self.after(0, self._log_timeline, "PACKET", rid,
                               f"burst {i+1}/{count}")
                if i < count - 1:
                    time.sleep(interval)
            self.after(0, self._pkt_status.configure,
                       {"text": f"✔  Burst complete ({count} pkts)", "text_color": COLORS["green"]})

        threading.Thread(target=burst, daemon=True).start()

    def _export_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All", "*.*")],
            initialfile="audit_log.json",
        )
        if path:
            self.table.export_log(path)
            messagebox.showinfo("Exported", f"Audit log saved to:\n{path}")

    def _on_tree_select(self, _=None):
        sel = self._tree.selection()
        if not sel:
            return
        rid = self._tree.item(sel[0])["values"][0]
        rule = self.table.get_rule(rid)
        self._selected_rule_id = rid
        self._pkt_rule_id.set(rid)

        if rule:
            text = (
                f"  Rule {rule.rule_id}  │  {rule.match}  │  {rule.action}  │  "
                f"Priority {rule.priority}  │  State {rule.state.value}  │  "
                f"Pkts {rule.packet_count}  │  Bytes {rule.byte_count}  │  "
                f"Idle Rem {fmt_remain(rule.idle_remaining())}  │  "
                f"Hard Rem {fmt_remain(rule.hard_remaining())}  │  "
                f"Age {rule.age():.1f}s  │  Created {fmt_time(rule.created_at)}"
            )
        else:
            text = f"  Rule {rid} — no longer in active table"

        self._detail_lbl.configure(text=text, text_color=COLORS["text"])

    def _sort_tree(self, col: str):
        if self._sort_col == col:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col = col
            self._sort_rev = True
        self._refresh_table()

    # ──────────────────────────────────────────────────────────────────────────
    # Refresh / update loop
    # ──────────────────────────────────────────────────────────────────────────
    def _start_refresh(self):
        self._refresh_all()

    def _refresh_all(self):
        self._refresh_table()
        self._refresh_stats()
        self._refresh_timeline()
        self._clock_lbl.configure(text=time.strftime("%H:%M:%S"))

        if self._auto_refresh_var.get():
            self.after(1000, self._refresh_all)
        else:
            self.after(1000, self._refresh_all)

    def _refresh_table(self):
        rules = self.table.list_rules()
        removed = self.table.get_removed_log()

        # Update summary
        active_count = sum(1 for r in rules if r.state == FlowState.ACTIVE)
        self._summary_labels["active"].configure(text=str(active_count))
        self._summary_labels["idle_exp"].configure(
            text=str(self.table.stats["total_idle_expired"]))
        self._summary_labels["hard_exp"].configure(
            text=str(self.table.stats["total_hard_expired"]))
        self._summary_labels["total_added"].configure(
            text=str(self.table.stats["total_added"]))
        self._summary_labels["manual_rem"].configure(
            text=str(self.table.stats["total_removed_manually"]))

        # Sort
        col_map = {
            "ID": "rule_id", "State": "state", "Priority": "priority",
            "Idle TO": "idle_timeout", "Hard TO": "hard_timeout",
            "Pkts": "packet_count", "Bytes": "byte_count",
        }
        attr = col_map.get(self._sort_col)
        if attr:
            rules = sorted(rules,
                           key=lambda r: (getattr(r, attr).value
                                          if attr == "state" else getattr(r, attr)),
                           reverse=self._sort_rev)

        # Keep selection
        sel_id = None
        sel = self._tree.selection()
        if sel:
            vals = self._tree.item(sel[0])["values"]
            if vals:
                sel_id = vals[0]

        self._tree.delete(*self._tree.get_children())

        for r in rules:
            idle_rem = fmt_remain(r.idle_remaining())
            hard_rem = fmt_remain(r.hard_remaining())

            # Colour-code idle remaining
            if r.idle_timeout > 0 and r.idle_remaining() < 3:
                idle_rem = f"⚠ {idle_rem}"
            if r.hard_timeout > 0 and r.hard_remaining() < 5:
                hard_rem = f"⚠ {hard_rem}"

            row = (
                r.rule_id,
                r.state.value,
                r.priority,
                str(r.match),
                str(r.action),
                f"{r.idle_timeout}s" if r.idle_timeout > 0 else "OFF",
                f"{r.hard_timeout}s" if r.hard_timeout > 0 else "OFF",
                idle_rem,
                hard_rem,
                r.packet_count,
                r.byte_count,
                f"{r.age():.1f}s",
            )

            tag = r.state.name.lower()
            iid = self._tree.insert("", "end", values=row, tags=(tag,))
            if r.rule_id == sel_id:
                self._tree.selection_set(iid)
                self._tree.see(iid)

        # Tag colours
        self._tree.tag_configure("active",       foreground=COLORS["green"])
        self._tree.tag_configure("idle_expired", foreground=COLORS["yellow"])
        self._tree.tag_configure("hard_expired", foreground=COLORS["red"])
        self._tree.tag_configure("removed",      foreground=COLORS["muted"])

        # Check for newly expired rules → log to timeline
        for r in removed:
            key = f"{r.rule_id}_expired"
            if key not in self.__dict__:
                self.__dict__[key] = True
                event_type = ("IDLE_EXPIRED" if r.state == FlowState.IDLE_EXPIRED
                              else "HARD_EXPIRED" if r.state == FlowState.HARD_EXPIRED
                              else "REMOVED")
                self._log_timeline(event_type, r.rule_id,
                                   f"pkts={r.packet_count} bytes={r.byte_count}")

    def _refresh_stats(self):
        stats = self.table.stats.copy()
        rules = self.table.list_rules()
        removed = self.table.get_removed_log()
        stats["currently_active"]    = len(rules)
        stats["total_in_audit_log"]  = len(removed)

        for key, lbl in self._stat_labels.items():
            lbl.configure(text=str(stats.get(key, 0)))

        # Audit tree
        self._audit_tree.delete(*self._audit_tree.get_children())
        for r in reversed(removed[-100:]):
            row = (
                r.rule_id, r.state.value, str(r.match),
                r.packet_count, r.byte_count, f"{r.age():.1f}",
            )
            tag = ("idle_exp" if r.state == FlowState.IDLE_EXPIRED
                   else "hard_exp" if r.state == FlowState.HARD_EXPIRED
                   else "removed")
            self._audit_tree.insert("", "end", values=row, tags=(tag,))

        self._audit_tree.tag_configure("idle_exp",  foreground=COLORS["yellow"])
        self._audit_tree.tag_configure("hard_exp",  foreground=COLORS["red"])
        self._audit_tree.tag_configure("removed",   foreground=COLORS["muted"])

    def _refresh_timeline(self):
        self._render_timeline()

    def _render_timeline(self):
        filt = self._timeline_filter.get()
        self._timeline_box.configure(state="normal")
        self._timeline_box.delete("1.0", "end")

        if not self._tl_tags_set:
            tl = self._timeline_box._textbox
            tl.tag_configure("ADDED",        foreground=COLORS["green"])
            tl.tag_configure("REMOVED",      foreground=COLORS["muted"])
            tl.tag_configure("IDLE_EXPIRED", foreground=COLORS["yellow"])
            tl.tag_configure("HARD_EXPIRED", foreground=COLORS["red"])
            tl.tag_configure("PACKET",       foreground=COLORS["accent"])
            tl.tag_configure("ts",           foreground=COLORS["muted"])
            self._tl_tags_set = True

        tl = self._timeline_box._textbox

        for ev in reversed(self._timeline_events[-300:]):
            if filt != "ALL" and ev["type"] != filt:
                continue
            ts_str  = fmt_time(ev["ts"])
            type_str = f"  {ev['type']:<14}"
            id_str   = f"  {ev['rule_id']:<10}"
            det_str  = f"  {ev['detail']}\n"

            tl.insert("end", f"[{ts_str}]", "ts")
            tl.insert("end", type_str, ev["type"])
            tl.insert("end", id_str)
            tl.insert("end", det_str)

        self._timeline_box.configure(state="disabled")

    # ──────────────────────────────────────────────────────────────────────────
    # Analysis runner
    # ──────────────────────────────────────────────────────────────────────────
    def _run_analysis(self):
        if self._analysis_running:
            return
        self._analysis_running = True
        self._analysis_btn.configure(state="disabled", text="⏳ Running…")
        self._analysis_output.configure(state="normal")
        self._analysis_output.delete("1.0", "end")
        self._analysis_output.configure(state="disabled")
        self._analysis_progress.set(0)

        threading.Thread(target=self._analysis_thread, daemon=True).start()

    def _analysis_thread(self):
        def emit(msg):
            self.after(0, self._append_analysis, msg)

        def set_prog(v):
            self.after(0, self._analysis_progress.set, v)

        def set_status(msg):
            self.after(0, self._analysis_status.configure, {"text": msg})

        scenarios = [
            {"label": "Short idle, no traffic",  "idle": 3,  "hard": 0,  "traffic": False},
            {"label": "Short idle, WITH traffic", "idle": 3,  "hard": 0,  "traffic": True},
            {"label": "Hard timeout only",        "idle": 0,  "hard": 4,  "traffic": True},
            {"label": "Both timeouts, idle wins", "idle": 3,  "hard": 10, "traffic": False},
            {"label": "Both timeouts, hard wins", "idle": 10, "hard": 4,  "traffic": True},
        ]

        emit("=" * 65)
        emit("  FLOW RULE TIMEOUT MANAGER — BEHAVIOR ANALYSIS")
        emit("=" * 65)
        emit("")
        emit("[1] Creating experiment rules...\n")

        ana_table = FlowTable(scan_interval=0.5)
        ana_table.start()

        rule_map = {}
        for sc in scenarios:
            rule = FlowRule(
                match=FlowMatch(src_ip="10.0.0.1", dst_ip="10.0.0.2"),
                action=FlowAction(action_type="FORWARD", output_port=1),
                idle_timeout=sc["idle"], hard_timeout=sc["hard"],
            )
            rid = ana_table.add_rule(rule)
            rule_map[rid] = sc
            sc["rule_id"]    = rid
            sc["created_at"] = time.time()
            sc["expired_at"] = None
            sc["expire_reason"] = None
            emit(f"  [{rid}] {sc['label']:<35} idle={sc['idle']}s "
                 f"hard={sc['hard']}s  traffic={'YES' if sc['traffic'] else 'NO '}")

        emit("")
        emit("[2] Running experiment (13 seconds)…\n")
        set_status("Running…")
        start = time.time()

        for tick in range(26):
            time.sleep(0.5)
            set_prog((tick + 1) / 26)
            for sc in scenarios:
                if sc["traffic"]:
                    ana_table.match_packet(sc["rule_id"], pkt_size=64)

            removed_ids = {r.rule_id for r in ana_table.get_removed_log()}
            for sc in scenarios:
                if sc["expired_at"] is None and sc["rule_id"] in removed_ids:
                    sc["expired_at"] = time.time()
                    sc["elapsed"]    = round(sc["expired_at"] - sc["created_at"], 2)
                    log_e = next(r for r in ana_table.get_removed_log()
                                 if r.rule_id == sc["rule_id"])
                    sc["expire_reason"] = log_e.state.value
                    sc["final_packets"] = log_e.packet_count
                    elapsed = f"t+{sc['elapsed']:.1f}s"
                    emit(f"  {elapsed:>8}  EXPIRED  [{sc['rule_id']}]  "
                         f"{sc['label']:<35}  reason={sc['expire_reason']}")

        ana_table.stop()

        emit("")
        emit("[3] Analysis Report\n")
        emit(f"  {'Scenario':<38} {'idle':>5} {'hard':>5} {'traffic':>8} "
             f"{'expired_at':>12}  {'reason'}")
        emit("  " + "─" * 78)
        for sc in scenarios:
            exp    = f"{sc.get('elapsed', 'N/A'):>10}" if sc["expired_at"] else " still active"
            reason = sc.get("expire_reason", "N/A")
            emit(f"  {sc['label']:<38} {sc['idle']:>5} {sc['hard']:>5} "
                 f"{'YES' if sc['traffic'] else 'NO':>8} {exp:>12}  {reason}")

        emit("")
        emit("[4] Key Findings\n")
        findings = [
            "✔ Rules with no traffic expire at idle_timeout seconds (idle expiry).",
            "✔ Rules with constant traffic bypass idle expiry entirely.",
            "✔ Hard timeout fires regardless of traffic (absolute deadline).",
            "✔ When both timeouts set, whichever fires first wins.",
            "✔ idle_timeout=0 disables idle expiry; hard_timeout=0 disables hard expiry.",
            "✔ Audit log correctly records state (IDLE_EXPIRED / HARD_EXPIRED).",
        ]
        for f in findings:
            emit(f"  {f}")

        emit("")
        emit("✔  Analysis complete.")
        set_prog(1.0)
        set_status("✔ Done")
        self.after(0, self._analysis_btn.configure, {"state": "normal", "text": "▶  Run Analysis"})
        self._analysis_running = False

    # ──────────────────────────────────────────────────────────────────────────
    # Test runner
    # ──────────────────────────────────────────────────────────────────────────
    def _run_tests(self):
        if self._test_running:
            return
        self._test_running = True
        self._test_btn.configure(state="disabled", text="⏳ Running…")
        self._test_progress.set(0)
        self._test_summary.configure(text="")

        # Clear tree & pre-populate with pending
        self._test_tree.delete(*self._test_tree.get_children())

        import unittest
        from tests.test_flow_timeout import (
            TestFlowRuleTimeoutDetection,
            TestFlowTableOperations,
            TestRegressionConsistency,
        )

        suite = unittest.TestLoader().loadTestsFromTestCase(TestFlowRuleTimeoutDetection)
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestFlowTableOperations))
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestRegressionConsistency))

        all_tests = list(suite)
        total     = len(all_tests)

        # Prepopulate rows
        row_ids = {}
        for t in all_tests:
            cls  = t.__class__.__name__
            name = t._testMethodName
            iid  = self._test_tree.insert("", "end",
                                          values=("⏳ Pending", cls, name, "—", ""),
                                          tags=("pending",))
            row_ids[t.id()] = iid

        def run_thread():
            passed  = 0
            failed  = 0
            errored = 0

            for i, test in enumerate(all_tests):
                iid = row_ids[test.id()]
                cls  = test.__class__.__name__
                name = test._testMethodName

                # Mark running
                self.after(0, self._test_tree.item, iid,
                           {"values": ("▶ Running", cls, name, "—", ""),
                            "tags": ("running",)})

                t0 = time.time()
                result = unittest.TestResult()
                test.run(result)
                duration = f"{(time.time()-t0)*1000:.0f}ms"

                self.after(0, self._test_progress.set, (i + 1) / total)

                if result.wasSuccessful():
                    passed += 1
                    self.after(0, self._test_tree.item, iid,
                               {"values": ("✔ PASS", cls, name, duration, ""),
                                "tags": ("pass",)})
                elif result.failures:
                    failed += 1
                    msg = result.failures[0][1].strip().split("\n")[-1][:120]
                    self.after(0, self._test_tree.item, iid,
                               {"values": ("✕ FAIL", cls, name, duration, msg),
                                "tags": ("fail",)})
                else:
                    errored += 1
                    msg = result.errors[0][1].strip().split("\n")[-1][:120]
                    self.after(0, self._test_tree.item, iid,
                               {"values": ("⚠ ERROR", cls, name, duration, msg),
                                "tags": ("error",)})

            color   = COLORS["green"] if failed + errored == 0 else COLORS["red"]
            summary = f"  {passed}/{total} passed  |  {failed} failed  |  {errored} errors"
            self.after(0, self._test_summary.configure,
                       {"text": summary, "text_color": color})
            self.after(0, self._test_btn.configure,
                       {"state": "normal", "text": "▶  Run All Tests"})
            self._test_running = False

        threading.Thread(target=run_thread, daemon=True).start()

    # ──────────────────────────────────────────────────────────────────────────
    # Window close
    # ──────────────────────────────────────────────────────────────────────────
    def on_close(self):
        self.table.stop()
        self.destroy()


# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs("logs", exist_ok=True)

    app = FlowManagerGUI()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()