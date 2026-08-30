#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NFC Reader/Writer - a desktop tool for FeliCa and other NFC tags.

Three panels share one reader:

* **FeliCa Lite / Lite-S** - the full block editor: read every block, edit the
  user area, change per-block access rights, write the card key and permanently
  lock the card.
* **Type 3 Explorer** - works on any Type 3 tag including FeliCa Standard and
  Mobile FeliCa: enumerate systems, areas and services and read or write raw
  blocks through a chosen service code.
* **NDEF** - read and write NDEF messages on any tag type nfcpy supports
  (Type 1-5: Topaz, MIFARE Ultralight / NTAG, ISO 15693, FeliCa ...).

Source code, README, and full license (GNU GPL v3):
    https://github.com/HiroYokoyama/nfc-reader-writer
Copyright (c) HiroYokoyama. Licensed under the GNU General Public License;
see the LICENSE file in the repository above for the full terms.
"""
import argparse
import binascii
import hashlib
import hmac
import json
import queue
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

import felica_core as core
import felica_type3 as t3
import ndef_tools
from felica_core import (ALL_BLOCKS, BLOCK_CK, BLOCK_DESCRIPTIONS,
                         BLOCK_MC, BLOCK_NAMES, EDITABLE_BLOCKS,
                         FAILED_MARKER, FELICA_LITE_S_BLOCKS,
                         FELICA_LITE_S_BYTES, MARKERS, SKIPPED_MARKER,
                         SUPPORTED_ENCODINGS, MCBlockHandler, NfcController,
                         is_hex)

from version import APP_NAME, APP_VERSION, VERSION_STRING

__version__ = APP_VERSION

#: Version of the .json state format, which continues the numbering of the tool
#: this application replaces, so its exports (version 4.0 and older) still load.
JSON_FORMAT_VERSION = 5.0

HEX_NA_SKIPPED = "N/A (write-only)"
HEX_NA_FAILED = "N/A (read failed)"


def hex_to_ascii(chunk, encoding):
    try:
        return chunk.decode(encoding, errors="replace").replace("\x00", ".")
    except Exception:
        return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)


# ==============================================================================
# Tool windows
# ==============================================================================
class KeyGenWindow(tk.Toplevel):
    """Derives a 16-byte card key from an IDm and a passphrase."""

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Card Key Generator (16 bytes)")
        self.geometry("460x330")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.transient(app)
        self.grab_set()
        self.idm_var = tk.StringVar(value=app.card_idm())
        self.password_var = tk.StringVar()
        self.result_var = tk.StringVar(
            value="The generated 32-character key appears here.")
        self._create_widgets()

    def on_close(self):
        self.grab_release()
        self.destroy()

    def _create_widgets(self):
        frame = ttk.Frame(self, padding=15)
        frame.pack(fill="both", expand=True)

        idm_box = ttk.Labelframe(frame, text="FeliCa IDm (16 hex characters)")
        idm_box.pack(fill="x", pady=5)
        row = ttk.Frame(idm_box, padding=5)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.idm_var, font=("Courier New", 10)
                  ).pack(side="left", fill="x", expand=True, padx=(0, 5))
        ttk.Button(row, text="Read IDm", command=self.read_idm,
                   state="normal" if self.app.nfc_ready else "disabled"
                   ).pack(side="left")

        pw_box = ttk.Labelframe(frame, text="Passphrase (HMAC key)")
        pw_box.pack(fill="x", pady=5)
        ttk.Entry(pw_box, textvariable=self.password_var, show="•"
                  ).pack(fill="x", padx=5, pady=5)

        ttk.Button(frame, text="Generate card key (HMAC-SHA256)",
                   command=self.generate).pack(fill="x", pady=10)

        out_box = ttk.Labelframe(frame, text="Generated card key (CK)")
        out_box.pack(fill="x", pady=5)
        ttk.Label(out_box, textvariable=self.result_var, font=("Courier New", 10),
                  wraplength=400, justify="left").pack(fill="x", padx=5, pady=5)
        buttons = ttk.Frame(out_box)
        buttons.pack(fill="x", padx=5, pady=5)
        ttk.Button(buttons, text="Copy to clipboard", command=self.copy
                   ).pack(side="left", expand=True, fill="x", padx=(0, 5))
        ttk.Button(buttons, text="Use as card key", command=self.transfer
                   ).pack(side="left", expand=True, fill="x")

    def generate(self):
        idm = self.idm_var.get().strip().upper()
        password = self.password_var.get()
        if not is_hex(idm, 16):
            messagebox.showerror("Error", "The IDm must be 16 hex characters.",
                                 parent=self)
            return
        if not password:
            messagebox.showerror("Error", "A passphrase is required.", parent=self)
            return
        digest = hmac.new(password.encode("utf-8"), bytes.fromhex(idm),
                          hashlib.sha256).digest()[:16]
        self.result_var.set(digest.hex().upper())

    def read_idm(self):
        self.app.read_card_info(target=self.idm_var, parent=self)

    def copy(self):
        value = self.result_var.get()
        if not is_hex(value, 32):
            messagebox.showwarning("Warning", "No key has been generated yet.",
                                   parent=self)
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.app.log("INFO", "Card key copied to the clipboard.")

    def transfer(self):
        value = self.result_var.get()
        if not is_hex(value, 32):
            messagebox.showwarning("Warning", "No key has been generated yet.",
                                   parent=self)
            return
        self.app.set_card_key(value)
        self.on_close()


class AsciiHexConverterWindow(tk.Toplevel):
    """Converts text to a padded 16-byte hex block."""

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Text to HEX converter")
        self.geometry("470x260")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.transient(app)
        self.grab_set()

        self.style = ttk.Style(self)
        self.style.configure("Error.TEntry", fieldbackground="#FFCCCC")

        self.input_var = tk.StringVar()
        self.input_var.trace_add("write", self.on_change)
        self.encoding_var = tk.StringVar(value=app.encoding_var.get())
        self.output_var = tk.StringVar()
        self.length_var = tk.StringVar()
        self._create_widgets()
        self.on_change()

    def on_close(self):
        self.grab_release()
        self.destroy()

    def _create_widgets(self):
        frame = ttk.Frame(self, padding=15)
        frame.pack(fill="both", expand=True)

        in_box = ttk.Labelframe(frame, text="Input text")
        in_box.pack(fill="x", pady=5)
        row = ttk.Frame(in_box, padding=5)
        row.pack(fill="x")
        self.input_entry = ttk.Entry(row, textvariable=self.input_var,
                                     font=("Courier New", 10))
        self.input_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        menu = ttk.Combobox(row, textvariable=self.encoding_var,
                            values=SUPPORTED_ENCODINGS, width=10, state="readonly")
        menu.pack(side="left")
        menu.bind("<<ComboboxSelected>>", self.on_change)

        out_box = ttk.Labelframe(frame, text="Output (16 bytes)")
        out_box.pack(fill="x", pady=5)
        ttk.Label(out_box, textvariable=self.length_var).pack(anchor="w", padx=5)
        ttk.Entry(out_box, textvariable=self.output_var, font=("Courier New", 10),
                  state="readonly").pack(fill="x", padx=5, pady=5)

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=10)
        self.copy_button = ttk.Button(buttons, text="Copy to clipboard",
                                      command=self.copy)
        self.copy_button.pack(side="left", expand=True, fill="x", padx=(0, 5))
        self.transfer_button = ttk.Button(buttons, text="Put into selected block",
                                          command=self.transfer)
        self.transfer_button.pack(side="left", expand=True, fill="x")

    def on_change(self, *_args):
        text = self.input_var.get()
        try:
            encoded = text.encode(self.encoding_var.get())
        except Exception:
            self.output_var.set("Encoding error")
            self.length_var.set("Length: n/a")
            self.input_entry.config(style="Error.TEntry")
            self._enable(False)
            return
        if len(encoded) > 16:
            self.length_var.set("Length: %d/16 bytes (too long)" % len(encoded))
            self.output_var.set("ERROR: input is too long")
            self.input_entry.config(style="Error.TEntry")
            self._enable(False)
            return
        self.length_var.set("Length: %d bytes" % len(encoded))
        self.input_entry.config(style="TEntry")
        self.output_var.set(encoded.ljust(16, b"\x00").hex().upper())
        self._enable(True)

    def _enable(self, enabled):
        state = "normal" if enabled else "disabled"
        self.copy_button.config(state=state)
        self.transfer_button.config(state=state)

    def copy(self):
        self.clipboard_clear()
        self.clipboard_append(self.output_var.get())
        self.app.log("INFO", "16-byte hex data copied to the clipboard.")

    def transfer(self):
        if not self.app.set_selected_block_hex(self.output_var.get(), parent=self):
            return
        self.on_close()


# ==============================================================================
# Main application
# ==============================================================================
class NfcApp(tk.Tk):
    def __init__(self, test_file=None, test_mode=False, device="usb"):
        super().__init__()
        self.test_mode = test_mode or test_file is not None
        self.test_file_path = test_file
        self.device = device

        title = VERSION_STRING
        if self.test_mode:
            title += "  [TEST MODE - no reader used]"
        self.title(title)
        self.geometry("1320x800")
        self.minsize(1100, 640)

        self.out_q = queue.Queue()
        self._alive = True
        self._after_ids = set()
        self.busy = False
        self.card_info = {}
        self.mc_handler = MCBlockHandler()
        self.original_mc_state = self.mc_handler.state_snapshot()
        self.original_dump = {}
        self.dump_blocks = {}
        self.has_data_in_ui = False
        self.is_card_locked = False
        self.card_kind = None

        self.encoding_var = tk.StringVar(value=SUPPORTED_ENCODINGS[0])
        self.show_key_var = tk.BooleanVar(value=False)
        self.use_auth_key_var = tk.BooleanVar(value=False)

        self.nfc_controller = None
        self.nfc_error = None
        if not self.test_mode:
            try:
                self.nfc_controller = NfcController(
                    path=self.device,
                    logger=lambda level, text: self.out_q.put(("LOG", (level, text))))
            except Exception as exc:
                self.nfc_error = str(exc)
        self.explorer = t3.Type3Explorer(self.nfc_controller) if self.nfc_controller else None
        self.ndef_manager = ndef_tools.NdefManager(self.nfc_controller) if self.nfc_controller else None

        self._configure_styles()
        self._create_widgets()
        self._initialize_empty_table()
        self._update_ui_state()
        self._poll_queue()

        if self.nfc_error:
            self.log("ERROR", self.nfc_error)
        elif self.test_mode:
            self.log("INFO", "Test mode: the reader is never touched; writes are "
                             "simulated.")
            self._schedule(100, self.load_dummy_data)

    @property
    def nfc_ready(self):
        return self.nfc_controller is not None

    # -- styling and layout ----------------------------------------------
    def _configure_styles(self):
        self.style = ttk.Style(self)
        self.style.configure("Custom.Treeview", font=("Courier New", 11), rowheight=26)
        self.style.configure("Custom.Treeview.Heading",
                             font=("TkDefaultFont", 10, "bold"))
        self.style.configure("Danger.TButton", foreground="red",
                             font=("TkDefaultFont", 9, "bold"))

    def _create_widgets(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Card key generator...",
                               command=lambda: KeyGenWindow(self))
        tools_menu.add_command(label="Text to HEX converter...",
                               command=lambda: AsciiHexConverterWindow(self))
        tools_menu.add_separator()
        tools_menu.add_command(label="Clear card data", command=self.reset_state)
        tools_menu.add_command(label="Quit", command=self.destroy)
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

        outer = ttk.Panedwindow(self, orient="vertical")
        outer.pack(fill="both", expand=True, padx=8, pady=8)

        top = ttk.Frame(outer)
        outer.add(top, weight=4)

        self.notebook = ttk.Notebook(top)
        self.notebook.pack(side="left", fill="both", expand=True)
        self.felica_tab = ttk.Frame(self.notebook)
        self.type3_tab = ttk.Frame(self.notebook)
        self.ndef_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.felica_tab, text="FeliCa Lite / Lite-S")
        self.notebook.add(self.type3_tab, text="Type 3 Explorer")
        self.notebook.add(self.ndef_tab, text="NDEF")

        side = ttk.Frame(top, width=320)
        side.pack(side="right", fill="y", padx=(8, 0))
        self._create_card_info(side)

        log_frame = ttk.Labelframe(outer, text="Log")
        outer.add(log_frame, weight=1)
        self.txt_log = tk.Text(log_frame, wrap="word", height=8)
        self.txt_log.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scroll = ttk.Scrollbar(log_frame, orient="vertical",
                               command=self.txt_log.yview)
        scroll.pack(side="right", fill="y")
        self.txt_log.config(yscrollcommand=scroll.set)

        self._create_felica_tab()
        self._create_type3_tab()
        self._create_ndef_tab()

        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status_var, relief="sunken",
                  anchor="w").pack(fill="x", side="bottom")

    def _create_card_info(self, parent):
        info = ttk.Labelframe(parent, text="Card")
        info.pack(fill="x", pady=(0, 5))
        grid = ttk.Frame(info, padding=5)
        grid.pack(fill="x")
        self.info_labels = {}
        for row, (key, caption) in enumerate([
                ("product", "Type:"), ("sys_code", "System code:"),
                ("idm", "IDm:"), ("pmm", "PMm:"), ("lock", "Lock status:")]):
            ttk.Label(grid, text=caption).grid(row=row, column=0, sticky="w")
            label = ttk.Label(grid, text="-", font=("TkDefaultFont", 9, "bold"))
            label.grid(row=row, column=1, sticky="w", padx=6)
            self.info_labels[key] = label

        auth = ttk.Labelframe(parent, text="Authentication (FeliCa Lite / Lite-S)")
        auth.pack(fill="x", pady=5)
        inner = ttk.Frame(auth, padding=5)
        inner.pack(fill="x")
        ttk.Label(inner, text="Card key version (CKV, 4 hex):").pack(fill="x")
        self.entry_ckv = ttk.Entry(inner)
        self.entry_ckv.insert(0, "0000")
        self.entry_ckv.pack(fill="x", pady=(0, 5))
        ttk.Label(inner, text="Card key (CK, 32 hex):").pack(fill="x")
        self.entry_key = ttk.Entry(inner, show="*")
        self.entry_key.pack(fill="x", pady=(0, 5))
        ttk.Checkbutton(inner, text="Show key", variable=self.show_key_var,
                        command=self.toggle_key_visibility).pack(fill="x")
        ttk.Checkbutton(inner, text="Use this key for protected reads/writes",
                        variable=self.use_auth_key_var).pack(fill="x", pady=(0, 5))
        self.write_key_button = ttk.Button(
            inner, text="Write as new card key (CK + CKV)", command=self.on_write_key)
        self.write_key_button.pack(fill="x", pady=(4, 0))

    # -- FeliCa tab -------------------------------------------------------
    def _create_felica_tab(self):
        container = ttk.Frame(self.felica_tab, padding=6)
        container.pack(fill="both", expand=True)

        options = ttk.Frame(container)
        options.pack(fill="x", pady=(0, 5))
        ttk.Label(options, text="ASCII encoding:").pack(side="left", padx=(0, 5))
        encoding_menu = ttk.Combobox(options, textvariable=self.encoding_var,
                                     values=SUPPORTED_ENCODINGS,
                                     state="readonly", width=12)
        encoding_menu.pack(side="left")
        encoding_menu.bind("<<ComboboxSelected>>", self._on_encoding_change)

        body = ttk.Frame(container)
        body.pack(fill="both", expand=True)

        table_frame = ttk.Frame(body)
        table_frame.pack(side="left", fill="both", expand=True)

        cols = ("block", "hex", "ascii", "access")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings",
                                 style="Custom.Treeview")
        for key, caption, width, stretch in [
                ("block", "Block", 130, False),
                ("hex", "Hex data (16 bytes)", 300, True),
                ("ascii", "ASCII / meaning", 240, True),
                ("access", "Access rights", 150, False)]:
            self.tree.heading(key, text=caption)
            self.tree.column(key, width=width, stretch=stretch,
                             anchor="w" if key in ("block", "ascii") else "center")
        self.tree.tag_configure("readonly", background="#EDEDED")
        self.tree.tag_configure("modified", background="#DCEEFB")
        vscroll = ttk.Scrollbar(table_frame, orient="vertical",
                                command=self.tree.yview)
        vscroll.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=vscroll.set)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", self.on_tree_double_click)
        self.tree.bind("<Button-1>", self.on_tree_click)
        self.tree.bind("<Motion>", self.on_tree_motion)
        self.tree.bind("<Leave>", self.on_tree_leave)
        self.tooltip_window = None

        ops = ttk.Labelframe(body, text="Operations", width=250)
        ops.pack(side="right", fill="y", padx=(8, 0))
        inner = ttk.Frame(ops, padding=8)
        inner.pack(fill="x")
        self.read_button = ttk.Button(inner, text="Read card",
                                      command=self.on_read_card)
        self.read_button.pack(fill="x", pady=2)
        self.write_button = ttk.Button(inner, text="Write changes to card",
                                       command=self.on_write_changes)
        self.write_button.pack(fill="x", pady=2)
        ttk.Separator(inner).pack(fill="x", pady=6)
        self.save_bin_button = ttk.Button(inner, text="Save dump (.bin)...",
                                          command=self.on_save_bin)
        self.save_bin_button.pack(fill="x", pady=2)
        ttk.Button(inner, text="Load dump (.bin)...", command=self.on_load_bin
                   ).pack(fill="x", pady=2)
        self.save_json_button = ttk.Button(inner, text="Save state (.json)...",
                                           command=self.on_save_json)
        self.save_json_button.pack(fill="x", pady=2)
        ttk.Button(inner, text="Load state (.json)...", command=self.on_load_json
                   ).pack(fill="x", pady=2)
        self.export_report_button = ttk.Button(inner, text="Export report (.txt)...",
                                               command=self.on_export_report)
        self.export_report_button.pack(fill="x", pady=2)
        ttk.Separator(inner).pack(fill="x", pady=6)
        self.lock_button = ttk.Button(inner, text="Permanently lock card...",
                                      command=self.on_lock_card,
                                      style="Danger.TButton")
        self.lock_button.pack(fill="x", pady=2)
        ttk.Label(inner, wraplength=210, foreground="#666666",
                  text="Locking sets MC[2] to 00h. The card key and the system "
                       "blocks can never be changed again.").pack(fill="x", pady=4)

    # -- Type 3 tab -------------------------------------------------------
    def _create_type3_tab(self):
        container = ttk.Frame(self.type3_tab, padding=6)
        container.pack(fill="both", expand=True)

        bar = ttk.Frame(container)
        bar.pack(fill="x", pady=(0, 6))
        self.t3_scan_button = ttk.Button(bar, text="Scan card",
                                         command=self.on_type3_scan)
        self.t3_scan_button.pack(side="left")
        self.t3_read_data_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Also dump block data of key-less services",
                        variable=self.t3_read_data_var).pack(side="left", padx=8)
        ttk.Button(bar, text="Save report (.txt)...", command=self.on_type3_save
                   ).pack(side="right")

        self.t3_text = tk.Text(container, wrap="none", font=("Courier New", 10))
        self.t3_text.pack(fill="both", expand=True)
        t3_scroll = ttk.Scrollbar(container, orient="horizontal",
                                  command=self.t3_text.xview)
        t3_scroll.pack(fill="x")
        self.t3_text.config(xscrollcommand=t3_scroll.set)
        self.t3_text.insert("1.0", "Place a Type 3 tag on the reader and press "
                                   "'Scan card'.\n")

        manual = ttk.Labelframe(container, text="Raw block access")
        manual.pack(fill="x", pady=(6, 0))
        row = ttk.Frame(manual, padding=6)
        row.pack(fill="x")
        ttk.Label(row, text="Service code (hex):").pack(side="left")
        self.t3_service_entry = ttk.Entry(row, width=8)
        self.t3_service_entry.insert(0, "000B")
        self.t3_service_entry.pack(side="left", padx=(4, 10))
        ttk.Label(row, text="Block:").pack(side="left")
        self.t3_block_entry = ttk.Entry(row, width=6)
        self.t3_block_entry.insert(0, "0")
        self.t3_block_entry.pack(side="left", padx=(4, 10))
        ttk.Label(row, text="Data (32 hex, write only):").pack(side="left")
        self.t3_data_entry = ttk.Entry(row, width=36, font=("Courier New", 10))
        self.t3_data_entry.pack(side="left", padx=(4, 10))
        self.t3_read_button = ttk.Button(row, text="Read block",
                                         command=self.on_type3_read_block)
        self.t3_read_button.pack(side="left", padx=2)
        self.t3_write_button = ttk.Button(row, text="Write block",
                                          command=self.on_type3_write_block)
        self.t3_write_button.pack(side="left", padx=2)

    # -- NDEF tab ---------------------------------------------------------
    def _create_ndef_tab(self):
        container = ttk.Frame(self.ndef_tab, padding=6)
        container.pack(fill="both", expand=True)

        bar = ttk.Frame(container)
        bar.pack(fill="x", pady=(0, 6))
        self.ndef_read_button = ttk.Button(bar, text="Read NDEF",
                                           command=self.on_ndef_read)
        self.ndef_read_button.pack(side="left")
        self.ndef_write_button = ttk.Button(bar, text="Write NDEF",
                                            command=self.on_ndef_write)
        self.ndef_write_button.pack(side="left", padx=6)
        self.ndef_format_button = ttk.Button(bar, text="Format tag for NDEF",
                                             command=self.on_ndef_format)
        self.ndef_format_button.pack(side="left")
        self.ndef_status_var = tk.StringVar(value="No tag read yet.")
        ttk.Label(bar, textvariable=self.ndef_status_var).pack(side="left", padx=12)

        columns = ("kind", "value")
        self.ndef_tree = ttk.Treeview(container, columns=columns, show="headings",
                                      height=8)
        self.ndef_tree.heading("kind", text="Record")
        self.ndef_tree.heading("value", text="Content")
        self.ndef_tree.column("kind", width=140, stretch=False)
        self.ndef_tree.column("value", width=700)
        self.ndef_tree.pack(fill="both", expand=True)

        editor = ttk.Labelframe(container, text="Record to write")
        editor.pack(fill="x", pady=(6, 0))
        row = ttk.Frame(editor, padding=6)
        row.pack(fill="x")
        ttk.Label(row, text="Type:").pack(side="left")
        self.ndef_kind_var = tk.StringVar(value="text")
        ttk.Combobox(row, textvariable=self.ndef_kind_var, width=8,
                     state="readonly", values=["text", "uri"]
                     ).pack(side="left", padx=(4, 10))
        ttk.Label(row, text="Language:").pack(side="left")
        self.ndef_lang_entry = ttk.Entry(row, width=5)
        self.ndef_lang_entry.insert(0, "en")
        self.ndef_lang_entry.pack(side="left", padx=(4, 10))
        ttk.Label(row, text="Value:").pack(side="left")
        self.ndef_value_entry = ttk.Entry(row)
        self.ndef_value_entry.pack(side="left", fill="x", expand=True, padx=4)

    # ======================================================================
    # Shared helpers
    # ======================================================================
    def reset_state(self):
        """Forget the current card and return every panel to its start state."""
        self.card_info = {}
        self.card_kind = None
        self.mc_handler = MCBlockHandler()
        self.original_mc_state = self.mc_handler.state_snapshot()
        self.original_dump.clear()
        self.dump_blocks.clear()
        self.has_data_in_ui = False
        self.is_card_locked = False
        for label in self.info_labels.values():
            label.config(text="-", foreground="")
        self.entry_ckv.delete(0, "end")
        self.entry_ckv.insert(0, "0000")
        self.entry_key.delete(0, "end")
        self.show_key_var.set(False)
        self.use_auth_key_var.set(False)
        self.toggle_key_visibility()
        self.encoding_var.set(SUPPORTED_ENCODINGS[0])
        self._destroy_cell_editors()
        self._initialize_empty_table()
        self.ndef_tree.delete(*self.ndef_tree.get_children())
        self.ndef_status_var.set("No tag read yet.")
        self._update_ui_state()

    def show_about(self):
        messagebox.showinfo(
            "About",
            "%s %s\n\nFeliCa Lite / Lite-S block editor, Type 3 (FeliCa "
            "Standard) explorer and NDEF reader/writer.\nBuilt on nfcpy.\n\n"
            "nfcpy available: %s" % (APP_NAME, APP_VERSION,
                                     "yes" if core.NFC_AVAILABLE else "no"),
            parent=self)

    def log(self, level, text):
        stamp = time.strftime("%H:%M:%S")
        self.txt_log.insert("end", "[%s] %s: %s\n" % (stamp, level, str(text).strip()))
        self.txt_log.see("end")

    def clear_log(self):
        self.txt_log.delete("1.0", "end")

    def toggle_key_visibility(self):
        self.entry_key.config(show="" if self.show_key_var.get() else "*")

    def card_idm(self):
        return self.card_info.get("idm", "")

    def set_card_key(self, key_hex):
        self.entry_key.delete(0, "end")
        self.entry_key.insert(0, key_hex)

    def key_bytes(self):
        """The card key from the UI, or None when it is unusable/disabled."""
        if not self.use_auth_key_var.get():
            return None
        key = self.entry_key.get().strip().upper()
        return binascii.unhexlify(key) if is_hex(key, 32) else None

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.out_q.get_nowait()
                if kind == "LOG":
                    self.log(payload[0], payload[1])
                elif kind == "STATUS":
                    self.status_var.set(payload)
                elif kind == "CARD_INFO":
                    self._apply_card_info(payload)
                elif kind == "DUMP":
                    self._populate_dump_table(payload)
                elif kind == "LOCK":
                    self._apply_lock_status(payload)
                elif kind == "BUSY":
                    self.busy = payload
                    self._update_ui_state()
                elif kind == "CALL":
                    payload()
        except queue.Empty:
            pass
        if self._alive:
            self._schedule(100, self._poll_queue)

    def _schedule(self, delay, callback):
        """``after`` that remembers its timer so destroy() can cancel it."""
        handle = None

        def run():
            self._after_ids.discard(handle)
            if self._alive:
                callback()

        handle = self.after(delay, run)
        self._after_ids.add(handle)
        return handle

    def destroy(self):
        """Cancel pending timers before tearing the interpreter down.

        A timer that fires into a destroyed window leaves the Tcl interpreter
        complaining about an invalid command name.
        """
        self._alive = False
        for handle in list(self._after_ids):
            try:
                self.after_cancel(handle)
            except Exception:
                pass
        self._after_ids.clear()
        super().destroy()

    def _run_worker(self, target, *args, **kwargs):
        """Run *target* on a background thread with the busy flag managed."""
        if self.busy:
            messagebox.showinfo("Busy", "Another card operation is still running.",
                                parent=self)
            return False

        def wrapper():
            try:
                target(*args, **kwargs)
            except Exception as exc:  # a worker crash must never be silent
                self.out_q.put(("LOG", ("ERROR", "Unexpected error: %s" % exc)))
                self.out_q.put(("CALL", lambda e=exc: messagebox.showerror(
                    "Error", "Unexpected error:\n%s" % e, parent=self)))
            finally:
                self.out_q.put(("BUSY", False))
                self.out_q.put(("STATUS", "Ready."))

        self.busy = True
        self._update_ui_state()
        self.status_var.set("Waiting for a card...")
        threading.Thread(target=wrapper, daemon=True).start()
        return True

    def _require_reader(self):
        if self.nfc_ready or self.test_mode:
            return True
        messagebox.showerror(
            "No reader",
            self.nfc_error or "The NFC reader is not available.", parent=self)
        return False

    def _update_ui_state(self):
        editable = "normal" if (self.has_data_in_ui and not self.busy) else "disabled"
        idle = "disabled" if self.busy else "normal"
        for widget in (self.write_button, self.save_bin_button,
                       self.save_json_button, self.export_report_button):
            widget.config(state=editable)
        self.read_button.config(state=idle)
        self.write_key_button.config(
            state="normal" if (not self.busy and not self.is_card_locked) else "disabled")
        self.lock_button.config(
            state="normal" if (self.has_data_in_ui and not self.busy
                               and not self.is_card_locked) else "disabled")
        for widget in (self.t3_scan_button, self.t3_read_button,
                       self.t3_write_button, self.ndef_read_button,
                       self.ndef_write_button, self.ndef_format_button):
            widget.config(state=idle)

    def _apply_card_info(self, info):
        self.card_info = dict(info or {})
        self.card_kind = self.card_info.get("kind")
        for key in ("product", "sys_code", "idm", "pmm"):
            value = self.card_info.get(key, "-") or "-"
            if key == "sys_code" and value != "-":
                value = "0x%s" % value
            self.info_labels[key].config(text=value)
        supports_lite_s = self.card_kind != core.KIND_LITE
        if self.card_kind in (core.KIND_LITE, core.KIND_LITE_S):
            self.mc_handler.supports_lite_s = supports_lite_s

    def _apply_lock_status(self, locked):
        self.is_card_locked = bool(locked)
        self.info_labels["lock"].config(
            text="LOCKED" if locked else "Unlocked",
            foreground="red" if locked else "green")
        self._update_ui_state()

    def read_card_info(self, target=None, parent=None):
        """Read only IDm/PMm; used by the key generator."""
        if not self._require_reader():
            return
        if self.test_mode:
            info = {"idm": "0123456789ABCDEF", "pmm": "0101010101010101",
                    "sys_code": "88B4", "product": "FeliCa Lite-S (simulated)",
                    "kind": core.KIND_LITE_S}
            self.out_q.put(("CARD_INFO", info))
            if target is not None:
                target.set(info["idm"])
            return

        def work():
            result = self.nfc_controller.get_card_info()
            if not result["ok"]:
                self.out_q.put(("CALL", lambda: messagebox.showerror(
                    "Failed", result["error"], parent=parent or self)))
                return
            info = result["data"]
            self.out_q.put(("CARD_INFO", info))
            if target is not None:
                self.out_q.put(("CALL", lambda: target.set(info["idm"])))

        self._run_worker(work)

    # ======================================================================
    # FeliCa tab: table handling
    # ======================================================================
    def _initialize_empty_table(self):
        self.tree.delete(*self.tree.get_children())
        for block_num in ALL_BLOCKS:
            label = "%3d / %02Xh %s" % (block_num, block_num,
                                        BLOCK_NAMES.get(block_num, ""))
            desc = BLOCK_DESCRIPTIONS.get(block_num, "")
            tags = () if block_num in EDITABLE_BLOCKS else ("readonly",)
            self.tree.insert("", "end", iid=str(block_num),
                             values=(label, "00" * 16, desc, ""), tags=tags)

    def _row_block(self, iid):
        return int(iid)

    def _populate_dump_table(self, dump_map):
        """Fill the table from ``{block: bytes}`` or a 256-byte user-area dump."""
        if isinstance(dump_map, (bytes, bytearray)):
            raw = bytes(dump_map)
            dump_map = {i: raw[i * 16:(i + 1) * 16]
                        for i in range(len(raw) // 16)
                        if raw[i * 16:(i + 1) * 16]}

        self._initialize_empty_table()
        self.dump_blocks = dict(dump_map)
        self.original_dump.clear()

        mc_data = dump_map.get(BLOCK_MC)
        if mc_data and mc_data not in MARKERS:
            self.mc_handler.parse_mc_block_data(mc_data)
            self._apply_lock_status(MCBlockHandler.is_locked(mc_data))
        self.original_mc_state = self.mc_handler.state_snapshot()

        encoding = self.encoding_var.get()
        for iid in self.tree.get_children():
            block_num = self._row_block(iid)
            values = list(self.tree.item(iid, "values"))
            chunk = dump_map.get(block_num)
            if chunk is None:
                hex_data = ""
                meaning = BLOCK_DESCRIPTIONS.get(block_num, "")
            elif chunk == SKIPPED_MARKER:
                hex_data = HEX_NA_SKIPPED
                meaning = BLOCK_DESCRIPTIONS.get(block_num, "")
            elif chunk == FAILED_MARKER:
                hex_data = HEX_NA_FAILED
                meaning = BLOCK_DESCRIPTIONS.get(block_num, "")
            else:
                chunk = bytes(chunk)[:16].ljust(16, b"\x00")
                hex_data = chunk.hex().upper()
                meaning = (BLOCK_DESCRIPTIONS.get(block_num)
                           or hex_to_ascii(chunk, encoding))
            values[1] = hex_data
            values[2] = meaning
            values[3] = self._format_access_string(block_num)
            self.tree.item(iid, values=tuple(values))
            self.original_dump[block_num] = hex_data

        self.has_data_in_ui = True
        self._update_ui_state()
        self._update_all_modified_statuses()

    def _format_access_string(self, block_num):
        if block_num >= self.mc_handler.max_blocks:
            return "system" if block_num >= 0x80 else ""
        base = "RW" if self.mc_handler.rw_ro_settings[block_num] else "RO"
        flags = []
        if self.mc_handler.r_auth_settings[block_num]:
            flags.append("RA")
        if self.mc_handler.rw_ro_settings[block_num]:
            if self.mc_handler.w_auth_settings[block_num]:
                flags.append("WA")
            if self.mc_handler.w_mac_settings[block_num]:
                flags.append("WM")
        return "%s [%s]" % (base, " ".join(flags)) if flags else base

    def _on_encoding_change(self, _event=None):
        encoding = self.encoding_var.get()
        for iid in self.tree.get_children():
            block_num = self._row_block(iid)
            if BLOCK_DESCRIPTIONS.get(block_num):
                continue
            values = list(self.tree.item(iid, "values"))
            if not is_hex(values[1], 32):
                continue
            values[2] = hex_to_ascii(binascii.unhexlify(values[1]), encoding)
            self.tree.item(iid, values=tuple(values))
        self.log("INFO", "ASCII column re-decoded as %s." % encoding)

    def _update_all_modified_statuses(self):
        for iid in self.tree.get_children():
            self._update_modified_status(iid)

    def _update_modified_status(self, iid):
        block_num = self._row_block(iid)
        values = self.tree.item(iid, "values")
        tags = set(self.tree.item(iid, "tags"))
        current = str(values[1]).upper()
        data_modified = (is_hex(current, 32)
                         and current != str(self.original_dump.get(block_num, "")).upper())

        rights_modified = False
        if block_num < self.mc_handler.max_blocks:
            original = self.original_mc_state
            handler = self.mc_handler
            rights_modified = any([
                handler.rw_ro_settings[block_num] != original["rw_ro"][block_num],
                handler.r_auth_settings[block_num] != original["r_auth"][block_num],
                handler.w_auth_settings[block_num] != original["w_auth"][block_num],
                handler.w_mac_settings[block_num] != original["w_mac"][block_num]])

        if data_modified or rights_modified:
            tags.add("modified")
        else:
            tags.discard("modified")
        self.tree.item(iid, tags=tuple(tags))

    def _mc_state_changed(self):
        return self.mc_handler.state_snapshot() != self.original_mc_state

    def _pending_data_changes(self):
        """``{block: hex}`` for user blocks whose hex differs from the card."""
        changes = {}
        for iid in self.tree.get_children():
            block_num = self._row_block(iid)
            if block_num not in EDITABLE_BLOCKS:
                continue
            hex_data = str(self.tree.item(iid, "values")[1]).upper()
            if not is_hex(hex_data, 32):
                continue
            if hex_data != str(self.original_dump.get(block_num, "")).upper():
                changes[block_num] = hex_data
        return changes

    # -- table interaction -------------------------------------------------
    def _destroy_cell_editors(self):
        for widget in self.tree.winfo_children():
            if isinstance(widget, (ttk.Combobox, ttk.Entry)):
                widget.destroy()

    def on_tree_click(self, event):
        self._destroy_cell_editors()
        if not self.has_data_in_ui or self.busy:
            return
        if self.tree.identify_region(event.x, event.y) != "cell":
            return
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.focus(iid)
        self.tree.selection_set(iid)
        if self.tree.identify_column(event.x) != "#4":
            return
        block_num = self._row_block(iid)
        if block_num >= self.mc_handler.max_blocks:
            return
        if self.is_card_locked:
            self.log("INFO", "Access rights cannot be changed on a locked card.")
            return
        self._show_access_editor(iid, self.tree.bbox(iid, "#4"))

    def _show_access_editor(self, iid, box):
        if not box:
            return
        block_num = self._row_block(iid)
        combo = ttk.Combobox(self.tree, state="readonly",
                             values=self.mc_handler.available_modes())
        combo.set(self.mc_handler.get_access_mode_string(block_num))
        combo.place(x=box[0], y=box[1], width=box[2], height=box[3])
        combo.focus()

        def on_select(_event):
            mode = combo.get()
            self.mc_handler.set_access_mode_from_string(block_num, mode)
            values = list(self.tree.item(iid, "values"))
            values[3] = self._format_access_string(block_num)
            self.tree.item(iid, values=tuple(values))
            self._update_all_modified_statuses()
            self.log("INFO", "Block %d access rights set to %s." % (block_num, mode))
            combo.destroy()

        combo.bind("<<ComboboxSelected>>", on_select)
        combo.bind("<FocusOut>",
                   lambda _e: combo.destroy() if combo.winfo_exists() else None)

    def on_tree_double_click(self, event):
        if not self.has_data_in_ui or self.busy:
            return
        if self.tree.identify_region(event.x, event.y) != "cell":
            return
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        column = self.tree.identify_column(event.x)
        block_num = self._row_block(iid)
        values = self.tree.item(iid, "values")

        if column == "#2":
            if block_num not in EDITABLE_BLOCKS:
                self.log("INFO", "Block %d is not editable here; use the "
                                 "dedicated controls." % block_num)
                return
            if self.is_card_locked:
                self.log("INFO", "Data cannot be modified on a locked card.")
                return
            if self.mc_handler.is_read_only(block_num):
                self.log("INFO", "Block %d is set to read-only (RO) on this card."
                         % block_num)
                return
            box = self.tree.bbox(iid, column)
            if not box:
                return
            entry = ttk.Entry(self.tree, font=("Courier New", 11), justify="center")
            entry.place(x=box[0], y=box[1], width=box[2], height=box[3])
            entry.insert(0, values[1] if is_hex(values[1], 32) else "00" * 16)
            entry.select_range(0, "end")
            entry.focus()
            entry.bind("<FocusOut>", lambda _e: self._save_cell_edit(iid, entry))
            entry.bind("<Return>", lambda _e: self._save_cell_edit(iid, entry))
            entry.bind("<Escape>", lambda _e: entry.destroy())
        elif column == "#3":
            self.clipboard_clear()
            self.clipboard_append(str(values[2]))
            self.log("INFO", "Copied the ASCII column of block %d." % block_num)

    def _save_cell_edit(self, iid, entry_widget):
        if not entry_widget.winfo_exists():
            return
        new_hex = entry_widget.get().strip().upper().replace(" ", "")
        entry_widget.destroy()
        block_num = self._row_block(iid)
        if not is_hex(new_hex, 32):
            self.log("ERROR", "Invalid data: a block needs exactly 32 hex "
                              "characters.")
            return
        values = list(self.tree.item(iid, "values"))
        values[1] = new_hex
        if not BLOCK_DESCRIPTIONS.get(block_num):
            values[2] = hex_to_ascii(binascii.unhexlify(new_hex),
                                     self.encoding_var.get())
        self.tree.item(iid, values=tuple(values))
        self._update_modified_status(iid)
        self.log("INFO", "Block %d updated in the table (not yet written)."
                 % block_num)

    def set_selected_block_hex(self, hex_value, parent=None):
        """Used by the converter window to push data into the selected row."""
        if not self.has_data_in_ui:
            messagebox.showwarning("No data", "Read a card or load a file first.",
                                   parent=parent or self)
            return False
        iid = self.tree.focus()
        if not iid:
            messagebox.showwarning("No selection", "Select a block first.",
                                   parent=parent or self)
            return False
        block_num = self._row_block(iid)
        if block_num not in EDITABLE_BLOCKS:
            messagebox.showwarning("Not editable",
                                   "Block %d cannot be edited directly." % block_num,
                                   parent=parent or self)
            return False
        if not is_hex(hex_value, 32):
            messagebox.showerror("Error", "The generated data is not 16 bytes.",
                                 parent=parent or self)
            return False
        values = list(self.tree.item(iid, "values"))
        values[1] = hex_value.upper()
        if not BLOCK_DESCRIPTIONS.get(block_num):
            values[2] = hex_to_ascii(binascii.unhexlify(hex_value),
                                     self.encoding_var.get())
        self.tree.item(iid, values=tuple(values))
        self._update_modified_status(iid)
        self.log("INFO", "Transferred data into block %d." % block_num)
        return True

    def on_tree_motion(self, event):
        self.on_tree_leave(event)
        iid = self.tree.identify_row(event.y)
        if not iid or self.tree.identify_column(event.x) != "#4":
            return
        block_num = self._row_block(iid)
        text = self._access_tooltip(block_num)
        if not text:
            return
        self.tooltip_window = window = tk.Toplevel(self)
        window.wm_overrideredirect(True)
        window.wm_geometry("+%d+%d" % (event.x_root + 15, event.y_root + 10))
        ttk.Label(window, text=text, justify="left", background="#FFFFE0",
                  relief="solid", borderwidth=1, padding=(5, 3)).pack()

    def on_tree_leave(self, _event=None):
        if self.tooltip_window is not None:
            self.tooltip_window.destroy()
            self.tooltip_window = None

    def _access_tooltip(self, block_num):
        if block_num >= self.mc_handler.max_blocks:
            return BLOCK_DESCRIPTIONS.get(block_num, "")
        handler = self.mc_handler
        is_rw = handler.rw_ro_settings[block_num]
        details = ["Read/Write (RW)" if is_rw else "Read-Only (RO)"]
        if handler.r_auth_settings[block_num]:
            details.append("• reading requires authentication")
        if is_rw and handler.w_auth_settings[block_num]:
            details.append("• writing requires authentication")
        if is_rw and handler.w_mac_settings[block_num]:
            details.append("• writing requires a MAC")
        if len(details) == 1:
            details.append("(no authentication needed)")
        return "\n".join(details)

    # ======================================================================
    # FeliCa tab: card operations
    # ======================================================================
    def load_dummy_data(self):
        if self.test_file_path:
            try:
                with open(self.test_file_path, "rb") as handle:
                    raw = handle.read()
                if len(raw) % 16:
                    raise ValueError("the dummy file must be a multiple of 16 bytes")
                dump = {i: raw[i * 16:(i + 1) * 16] for i in range(len(raw) // 16)}
                self.log("INFO", "Loaded dummy data from %s." % self.test_file_path)
            except Exception as exc:
                self.log("ERROR", "Could not load the dummy file: %s" % exc)
                return
        else:
            dump = {block: bytes([block]) * 16 for block in ALL_BLOCKS}
            dump[BLOCK_MC] = self.mc_handler.generate_mc_block_data()
            dump[BLOCK_CK] = SKIPPED_MARKER
            self.log("INFO", "Loaded simulated card data.")
        self._apply_card_info({"idm": "0123456789ABCDEF",
                               "pmm": "0101010101010101", "sys_code": "88B4",
                               "product": "FeliCa Lite-S (simulated)",
                               "kind": core.KIND_LITE_S})
        self._populate_dump_table(dump)

    def on_read_card(self):
        if self.test_mode:
            self.load_dummy_data()
            return
        if not self._require_reader():
            return

        key = self.key_bytes()

        def work():
            self.out_q.put(("STATUS", "Reading the card..."))
            self.out_q.put(("LOG", ("INFO", "Place the card on the reader...")))
            result = self.nfc_controller.read_card(key_bytes=key,
                                                   mc_handler=MCBlockHandler())
            if not result["ok"]:
                self.out_q.put(("LOG", ("ERROR", result["error"])))
                self.out_q.put(("CALL", lambda: messagebox.showerror(
                    "Read failed", result["error"], parent=self)))
                return
            data = result["data"]
            self.out_q.put(("CARD_INFO", data["info"]))
            self.out_q.put(("DUMP", data["blocks"]))
            self.out_q.put(("LOG", ("SUCCESS", "Card read: %d blocks."
                                    % len(data["blocks"]))))
            if not data["info"].get("supports_block_editor"):
                self.out_q.put(("CALL", lambda: messagebox.showinfo(
                    "Not a FeliCa Lite card",
                    "This card is a %s. The block editor is meant for FeliCa "
                    "Lite / Lite-S; use the Type 3 Explorer tab instead."
                    % data["info"].get("kind_label", "different card"),
                    parent=self)))

        self._run_worker(work)

    def on_write_changes(self):
        data_changes = self._pending_data_changes()
        mc_changed = self._mc_state_changed()
        if not data_changes and not mc_changed:
            messagebox.showinfo("No changes",
                                "No block data or access rights were modified.",
                                parent=self)
            return
        if self.is_card_locked:
            messagebox.showerror("Locked",
                                 "This card is permanently locked; nothing can "
                                 "be written.", parent=self)
            return
        if not self._require_reader():
            return

        writes = [(block, binascii.unhexlify(hex_data))
                  for block, hex_data in sorted(data_changes.items())]
        if mc_changed:
            writes.append((BLOCK_MC, self.mc_handler.generate_mc_block_data()))

        summary = ", ".join("%d" % block for block, _ in writes)
        if not messagebox.askokcancel(
                "Confirm write",
                "The following blocks will be written to the card:\n\n%s\n\n"
                "Proceed?" % summary, icon="warning", parent=self):
            return

        needs_key = any(self.mc_handler.needs_write_auth(block)
                        for block, _ in writes)
        key = self.key_bytes()
        if needs_key and not key:
            messagebox.showerror(
                "Card key required",
                "At least one block requires authentication. Enter a valid "
                "32-character card key and tick 'Use this key for protected "
                "reads/writes'.", parent=self)
            return

        if self.test_mode:
            self.log("INFO", "Test mode: simulated writing of blocks %s." % summary)
            self._after_successful_write(dict(data_changes), mc_changed)
            messagebox.showinfo("Test mode", "Writing was simulated.", parent=self)
            return

        handler = self.mc_handler

        def work():
            self.out_q.put(("STATUS", "Writing to the card..."))
            result = self.nfc_controller.write_blocks(writes, mc_handler=handler,
                                                      key_bytes=key)
            if not result["ok"]:
                self.out_q.put(("LOG", ("ERROR", result["error"])))
                self.out_q.put(("CALL", lambda: messagebox.showerror(
                    "Write failed", result["error"], parent=self)))
                return
            self.out_q.put(("LOG", ("SUCCESS", "All changes written.")))
            self.out_q.put(("CALL", lambda: self._after_successful_write(
                dict(data_changes), mc_changed)))
            self.out_q.put(("CALL", lambda: messagebox.showinfo(
                "Done", "The write cycle finished successfully.\nRe-read the card "
                        "to confirm.", parent=self)))

        self._run_worker(work)

    def _after_successful_write(self, data_changes, mc_changed):
        """Adopt the written values as the new baseline (main thread only)."""
        for block, hex_data in data_changes.items():
            self.original_dump[block] = hex_data
        if mc_changed:
            self.original_mc_state = self.mc_handler.state_snapshot()
            mc_hex = self.mc_handler.generate_mc_block_data().hex().upper()
            self.original_dump[BLOCK_MC] = mc_hex
            iid = str(BLOCK_MC)
            if self.tree.exists(iid):
                values = list(self.tree.item(iid, "values"))
                values[1] = mc_hex
                values[3] = self._format_access_string(BLOCK_MC)
                self.tree.item(iid, values=tuple(values))
        self._update_all_modified_statuses()

    def on_write_key(self):
        ckv_hex = self.entry_ckv.get().strip().upper()
        ck_hex = self.entry_key.get().strip().upper()
        if not is_hex(ckv_hex, 4):
            messagebox.showerror("Invalid input",
                                 "The CKV must be 4 hex characters.", parent=self)
            return
        if not is_hex(ck_hex, 32):
            messagebox.showerror("Invalid input",
                                 "The card key must be 32 hex characters.",
                                 parent=self)
            return
        if not messagebox.askokcancel(
                "Confirm card key write",
                "This overwrites the card key (block CK, 87h) and its version "
                "(block CKV, 86h).\n\nCK:  %s\nCKV: %s\n\nThe key cannot be read "
                "back, so store it safely. Proceed?" % (ck_hex, ckv_hex),
                icon="warning", parent=self):
            return
        if not self._require_reader():
            return
        if self.test_mode:
            self.log("SUCCESS", "Test mode: simulated card key write.")
            messagebox.showinfo("Test mode", "The key write was simulated.",
                                parent=self)
            return

        key = binascii.unhexlify(ck_hex)
        ckv = int(ckv_hex, 16)

        def work():
            self.out_q.put(("STATUS", "Writing the card key..."))
            result = self.nfc_controller.write_card_key(key, ckv)
            if not result["ok"]:
                self.out_q.put(("LOG", ("ERROR", result["error"])))
                self.out_q.put(("CALL", lambda: messagebox.showerror(
                    "Write failed", result["error"], parent=self)))
                return
            self.out_q.put(("LOG", ("SUCCESS",
                                    "Card key and CKV written (CKV=%04X)." % ckv)))
            self.out_q.put(("CALL", lambda: messagebox.showinfo(
                "Done", "The new card key is active. Re-read the card.",
                parent=self)))

        self._run_worker(work)

    def on_lock_card(self):
        message = "\n".join([
            "WARNING: this operation is irreversible.",
            "",
            "Setting MC[2] to 00h freezes the card key and the system blocks "
            "forever. If anything in the current configuration is wrong, the "
            "card can never be changed again.",
            "",
            "Are you absolutely sure?"])
        if not messagebox.askokcancel("FINAL CONFIRMATION: permanent lock",
                                      message, icon="warning", parent=self):
            self.log("INFO", "Lock cancelled.")
            return
        if not self._require_reader():
            return
        if self.test_mode:
            self.log("SUCCESS", "Test mode: simulated lock.")
            self._apply_lock_status(True)
            return

        def work():
            self.out_q.put(("STATUS", "Locking the card..."))
            result = self.nfc_controller.lock_card()
            if not result["ok"]:
                self.out_q.put(("LOG", ("ERROR", result["error"])))
                self.out_q.put(("CALL", lambda: messagebox.showerror(
                    "Lock failed", result["error"], parent=self)))
                return
            self.out_q.put(("LOG", ("SUCCESS", "The card is now permanently locked.")))
            self.out_q.put(("CALL", lambda: self._apply_lock_status(True)))

        self._run_worker(work)

    # ======================================================================
    # FeliCa tab: files
    # ======================================================================
    def _table_blocks(self):
        """``{block: bytes}`` for every row that currently holds real data."""
        blocks = {}
        for iid in self.tree.get_children():
            hex_data = str(self.tree.item(iid, "values")[1])
            if is_hex(hex_data, 32):
                blocks[self._row_block(iid)] = binascii.unhexlify(hex_data)
        return blocks

    def on_save_bin(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".bin", parent=self,
            filetypes=[("Binary dump", "*.bin"), ("All files", "*.*")],
            title="Save the user area (%d bytes)" % FELICA_LITE_S_BYTES)
        if not path:
            return
        try:
            blocks = self._table_blocks()
            buffer = bytearray(FELICA_LITE_S_BYTES)
            for block, data in blocks.items():
                if block < FELICA_LITE_S_BLOCKS:
                    buffer[block * 16:(block + 1) * 16] = data
            with open(path, "wb") as handle:
                handle.write(buffer)
            self.log("SUCCESS", "User-area dump saved to %s." % path)
        except Exception as exc:
            self.log("ERROR", "Could not save the dump: %s" % exc)
            messagebox.showerror("Save failed", str(exc), parent=self)

    def on_load_bin(self):
        path = filedialog.askopenfilename(
            defaultextension=".bin", parent=self,
            filetypes=[("Binary dump", "*.bin"), ("All files", "*.*")],
            title="Load a binary dump")
        if not path:
            return
        if not messagebox.askokcancel(
                "Confirm load",
                "This replaces the table contents. Nothing is written to a card "
                "until you press 'Write changes to card'.\n\nProceed?", parent=self):
            return
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
            if not raw or len(raw) % 16:
                raise ValueError("the file size must be a non-zero multiple of "
                                 "16 bytes")
            dump = {i: raw[i * 16:(i + 1) * 16] for i in range(len(raw) // 16)}
            keep = {block: data for block, data in self.dump_blocks.items()
                    if block not in dump}
            keep.update(dump)
            self._populate_dump_table(keep)
            self.log("SUCCESS", "Dump loaded from %s; changes are staged." % path)
        except Exception as exc:
            self.log("ERROR", "Could not load the dump: %s" % exc)
            messagebox.showerror("Load failed", str(exc), parent=self)

    def on_save_json(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json", parent=self,
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
            title="Save the full card state")
        if not path:
            return
        try:
            state = {
                "format_version": JSON_FORMAT_VERSION,
                "application": VERSION_STRING,
                "timestamp": datetime.now().isoformat(),
                "card_info": self.card_info,
                "lock_status": "LOCKED" if self.is_card_locked else "UNLOCKED",
                "ascii_encoding": self.encoding_var.get(),
                "authentication": {"ckv_hex": self.entry_ckv.get().strip().upper(),
                                   "ck_hex": self.entry_key.get().strip().upper()},
                "access_rights": {
                    "BLOCK_%d" % i: {
                        "RW_RO": self.mc_handler.rw_ro_settings[i],
                        "R_AUTH": self.mc_handler.r_auth_settings[i],
                        "W_AUTH": self.mc_handler.w_auth_settings[i],
                        "W_MAC": self.mc_handler.w_mac_settings[i],
                    } for i in range(self.mc_handler.max_blocks)},
                "data_blocks": {"BLOCK_%d" % block: data.hex().upper()
                                for block, data in sorted(self._table_blocks().items())},
            }
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(state, handle, indent=4)
            self.log("SUCCESS", "State saved to %s." % path)
        except Exception as exc:
            self.log("ERROR", "Could not save the state: %s" % exc)
            messagebox.showerror("Save failed", str(exc), parent=self)

    def on_load_json(self):
        path = filedialog.askopenfilename(
            defaultextension=".json", parent=self,
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
            title="Load a card state")
        if not path:
            return
        if not messagebox.askokcancel(
                "Confirm load", "This replaces the table and the access rights "
                                "shown. Nothing is written to a card until you "
                                "press 'Write changes to card'.\n\nProceed?",
                parent=self):
            return
        try:
            with open(path, "r", encoding="utf-8") as handle:
                state = json.load(handle)
            if float(state.get("format_version", 1.0)) > JSON_FORMAT_VERSION:
                raise ValueError("unsupported JSON format version %s"
                                 % state.get("format_version"))

            info = dict(state.get("card_info") or {})
            if info:
                self._apply_card_info(info)
            auth = state.get("authentication", {})
            self.entry_ckv.delete(0, "end")
            self.entry_ckv.insert(0, auth.get("ckv_hex", "0000"))
            self.entry_key.delete(0, "end")
            self.entry_key.insert(0, auth.get("ck_hex", ""))
            if state.get("ascii_encoding") in SUPPORTED_ENCODINGS:
                self.encoding_var.set(state["ascii_encoding"])

            rights = state.get("access_rights", {})
            for i in range(self.mc_handler.max_blocks):
                cfg = rights.get("BLOCK_%d" % i)
                if isinstance(cfg, dict):
                    self.mc_handler.rw_ro_settings[i] = int(cfg.get("RW_RO", 1))
                    self.mc_handler.r_auth_settings[i] = int(cfg.get("R_AUTH", 0))
                    self.mc_handler.w_auth_settings[i] = int(cfg.get("W_AUTH", 0))
                    self.mc_handler.w_mac_settings[i] = int(cfg.get("W_MAC", 0))

            dump = {}
            for key, hex_data in (state.get("data_blocks") or {}).items():
                try:
                    block = int(str(key).replace("BLOCK_", ""))
                except ValueError:
                    continue
                if is_hex(str(hex_data), 32):
                    dump[block] = binascii.unhexlify(hex_data)

            # The MC block in the file may disagree with the access-rights
            # section; the explicit access rights win.
            dump.pop(BLOCK_MC, None)
            self._populate_dump_table(dump)
            self._apply_lock_status(state.get("lock_status") == "LOCKED")
            self.original_mc_state = {k: [0] * self.mc_handler.max_blocks
                                      for k in ("rw_ro", "r_auth", "w_auth", "w_mac")}
            self._update_all_modified_statuses()
            self.log("SUCCESS", "State loaded from %s; changes are staged." % path)
        except Exception as exc:
            self.log("ERROR", "Could not load the state: %s" % exc)
            messagebox.showerror("Load failed", str(exc), parent=self)

    def on_export_report(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", parent=self,
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            title="Export a configuration report")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(self.build_report()))
            self.log("SUCCESS", "Report exported to %s." % path)
        except Exception as exc:
            self.log("ERROR", "Could not export the report: %s" % exc)
            messagebox.showerror("Export failed", str(exc), parent=self)

    def build_report(self):
        encoding = self.encoding_var.get()
        lines = [
            "#" * 72,
            "# %s - card report" % VERSION_STRING,
            "# Generated: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "#" * 72,
            "Card type:          %s" % self.card_info.get("product", "-"),
            "IDm:                %s" % self.card_info.get("idm", "-"),
            "PMm:                %s" % self.card_info.get("pmm", "-"),
            "System code:        %s" % self.card_info.get("sys_code", "-"),
            "Permanently locked: %s" % ("YES" if self.is_card_locked else "NO"),
            "CKV (UI field):     %s" % self.entry_ckv.get().strip().upper(),
            "ASCII decoding:     %s" % encoding.upper(),
            "",
            "--- ACCESS RIGHTS (S_PAD0..REG) ---",
            "%-7s | %-5s | %-6s | %-6s | %-5s | %s"
            % ("Block", "RW/RO", "R_AUTH", "W_AUTH", "W_MAC", "Mode"),
            "-" * 72,
        ]
        for i in range(self.mc_handler.max_blocks):
            lines.append("%-7s | %-5s | %-6s | %-6s | %-5s | %s" % (
                BLOCK_NAMES.get(i, str(i)),
                "RW" if self.mc_handler.rw_ro_settings[i] else "RO",
                "YES" if self.mc_handler.r_auth_settings[i] else "NO",
                "YES" if self.mc_handler.w_auth_settings[i] else "NO",
                "YES" if self.mc_handler.w_mac_settings[i] else "NO",
                self.mc_handler.get_access_mode_string(i)))

        lines += ["", "--- BLOCK DUMP ---",
                  "%-16s | %-32s | %-22s | %s"
                  % ("Block", "Hex data", "ASCII / meaning", "Access"),
                  "-" * 90]
        for iid in self.tree.get_children():
            values = self.tree.item(iid, "values")
            lines.append("%-16s | %-32s | %-22s | %s"
                         % (values[0], values[1], values[2], values[3]))
        return lines

    # ======================================================================
    # Type 3 tab
    # ======================================================================
    def _t3_set_text(self, lines):
        self.t3_text.delete("1.0", "end")
        self.t3_text.insert("1.0", "\n".join(lines) + "\n")

    def on_type3_scan(self):
        if not self._require_reader():
            return
        if self.test_mode:
            self._t3_set_text(["Test mode: no reader is used.",
                               "Connect a reader and start without --test to "
                               "scan a real card."])
            return
        read_data = self.t3_read_data_var.get()

        def work():
            self.out_q.put(("STATUS", "Scanning the card..."))
            result = self.explorer.explore(read_data=read_data)
            if not result["ok"]:
                self.out_q.put(("LOG", ("ERROR", result["error"])))
                self.out_q.put(("CALL", lambda: messagebox.showerror(
                    "Scan failed", result["error"], parent=self)))
                return
            report = result["data"]
            lines = t3.format_explore_report(report)
            self.out_q.put(("CARD_INFO", report["info"]))
            self.out_q.put(("CALL", lambda: self._t3_set_text(lines)))
            self.out_q.put(("LOG", ("SUCCESS", "Scan complete: %d system(s)."
                                    % len(report["systems"]))))

        self._run_worker(work)

    def on_type3_save(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", parent=self,
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            title="Save the explorer report")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.t3_text.get("1.0", "end"))
            self.log("SUCCESS", "Explorer report saved to %s." % path)
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc), parent=self)

    def _t3_inputs(self, need_data=False):
        try:
            service = t3.parse_service_code(self.t3_service_entry.get())
        except ValueError as exc:
            messagebox.showerror("Invalid service code", str(exc), parent=self)
            return None
        try:
            block = int(self.t3_block_entry.get().strip(), 0)
            if not 0 <= block <= 0xFFFF:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid block",
                                 "The block number must be 0..65535.", parent=self)
            return None
        payload = None
        if need_data:
            data_hex = self.t3_data_entry.get().strip().upper().replace(" ", "")
            if not is_hex(data_hex, 32):
                messagebox.showerror("Invalid data",
                                     "The data must be 32 hex characters "
                                     "(16 bytes).", parent=self)
                return None
            payload = binascii.unhexlify(data_hex)
        return service, block, payload

    def on_type3_read_block(self):
        if not self._require_reader():
            return
        parsed = self._t3_inputs()
        if not parsed:
            return
        service, block, _ = parsed
        if self.test_mode:
            self.log("INFO", "Test mode: simulated read of block %d." % block)
            return

        def work():
            result = self.explorer.read(service, [block])
            if not result["ok"]:
                self.out_q.put(("LOG", ("ERROR", result["error"])))
                return
            data = result["data"][block]
            printable = hex_to_ascii(data, self.encoding_var.get())
            self.out_q.put(("LOG", ("SUCCESS", "Service %04X block %d: %s |%s|"
                                    % (service, block, data.hex().upper(), printable))))
            self.out_q.put(("CALL", lambda: self.t3_data_entry.delete(0, "end")))
            self.out_q.put(("CALL",
                            lambda: self.t3_data_entry.insert(0, data.hex().upper())))

        self._run_worker(work)

    def on_type3_write_block(self):
        if not self._require_reader():
            return
        parsed = self._t3_inputs(need_data=True)
        if not parsed:
            return
        service, block, payload = parsed
        if not messagebox.askokcancel(
                "Confirm raw write",
                "Write %s\nto block %d through service %04X?\n\nA wrong service "
                "code or block number can corrupt the card."
                % (payload.hex().upper(), block, service),
                icon="warning", parent=self):
            return
        if self.test_mode:
            self.log("INFO", "Test mode: simulated write to block %d." % block)
            return

        def work():
            result = self.explorer.write(service, block, payload)
            if not result["ok"]:
                self.out_q.put(("LOG", ("ERROR", result["error"])))
                self.out_q.put(("CALL", lambda: messagebox.showerror(
                    "Write failed", result["error"], parent=self)))
                return
            self.out_q.put(("LOG", ("SUCCESS", "Service %04X block %d written."
                                    % (service, block))))

        self._run_worker(work)

    # ======================================================================
    # NDEF tab
    # ======================================================================
    def _show_ndef(self, data):
        self.ndef_tree.delete(*self.ndef_tree.get_children())
        if not data.get("formatted"):
            self.ndef_status_var.set("This tag carries no NDEF area.")
            return
        for record in data["records"]:
            self.ndef_tree.insert("", "end",
                                  values=(record["kind"], record["text"]))
        self.ndef_status_var.set(
            "%d record(s), %d of %d bytes used, %s"
            % (len(data["records"]), data["length"], data["capacity"],
               "writeable" if data["writeable"] else "read-only"))

    def on_ndef_read(self):
        if not self._require_reader():
            return
        if self.test_mode:
            self._show_ndef({"formatted": True, "length": 12, "capacity": 48,
                             "writeable": True,
                             "records": [{"kind": "Text",
                                          "text": "simulated  [en]"}]})
            return

        def work():
            self.out_q.put(("STATUS", "Reading NDEF..."))
            result = self.ndef_manager.read()
            if not result["ok"]:
                self.out_q.put(("LOG", ("ERROR", result["error"])))
                self.out_q.put(("CALL", lambda: messagebox.showerror(
                    "Read failed", result["error"], parent=self)))
                return
            data = result["data"]
            self.out_q.put(("CARD_INFO", data["info"]))
            self.out_q.put(("CALL", lambda: self._show_ndef(data)))
            self.out_q.put(("LOG", ("SUCCESS", "NDEF read: %d record(s)."
                                    % len(data["records"]))))

        self._run_worker(work)

    def on_ndef_write(self):
        if not self._require_reader():
            return
        value = self.ndef_value_entry.get()
        if not value:
            messagebox.showerror("Nothing to write",
                                 "Enter the text or URI to store.", parent=self)
            return
        spec = {"kind": self.ndef_kind_var.get(), "value": value,
                "language": self.ndef_lang_entry.get().strip() or "en"}
        if self.test_mode:
            self.log("INFO", "Test mode: simulated NDEF write (%s)." % value)
            return

        def work():
            self.out_q.put(("STATUS", "Writing NDEF..."))
            result = self.ndef_manager.write([spec])
            if not result["ok"]:
                self.out_q.put(("LOG", ("ERROR", result["error"])))
                self.out_q.put(("CALL", lambda: messagebox.showerror(
                    "Write failed", result["error"], parent=self)))
                return
            self.out_q.put(("LOG", ("SUCCESS", "NDEF message written (%d bytes)."
                                    % result["data"]["written"])))

        self._run_worker(work)

    def on_ndef_format(self):
        if not self._require_reader():
            return
        if not messagebox.askokcancel(
                "Confirm format",
                "Formatting writes a fresh, empty NDEF structure and destroys "
                "the current NDEF content.\n\nProceed?", icon="warning",
                parent=self):
            return
        if self.test_mode:
            self.log("INFO", "Test mode: simulated NDEF format.")
            return

        def work():
            result = self.ndef_manager.format()
            if not result["ok"]:
                self.out_q.put(("LOG", ("ERROR", result["error"])))
                self.out_q.put(("CALL", lambda: messagebox.showerror(
                    "Format failed", result["error"], parent=self)))
                return
            data = result["data"]
            self.out_q.put(("CALL", lambda: self._show_ndef(data)))
            self.out_q.put(("LOG", ("SUCCESS", "The tag was formatted for NDEF.")))

        self._run_worker(work)


def main(argv=None):
    parser = argparse.ArgumentParser(description="%s - FeliCa and NDEF tool."
                                                 % APP_NAME)
    parser.add_argument("--test", nargs="?", const="", metavar="DUMP_FILE",
                        help="run without a reader; optionally seed the table "
                             "from a binary dump")
    parser.add_argument("--device", default="usb",
                        help="nfcpy device path (default: usb)")
    parser.add_argument("--version", action="version", version=VERSION_STRING)
    args = parser.parse_args(argv)

    test_file = args.test or None
    app = NfcApp(test_file=test_file, test_mode=args.test is not None,
                 device=args.device)
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
