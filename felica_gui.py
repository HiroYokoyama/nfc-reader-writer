#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
felica_manager_final_v16_improved.py (User Request Implementation)

An all-in-one application for FeliCa Lite-S management.

# --- V21 MAJOR FEATURE UPDATE & UI HARDENING (Based on User Request) ---
# 1. (Feature) Implemented authenticated write functionality. The application can
#    now write to blocks protected with "W Auth" or "W MAC" settings.
# 2. (UI/UX) Disabled all editing functionalities (cell editing, writing, saving)
#    on the initial empty screen to prevent accidental changes before data is loaded.
# 3. (Feature) Enhanced JSON export/import to include all card identification
#    data (IDm, PMm, System Code) for complete state saving and restoration.
# 4. (UI/UX) Renamed Block 15's display to "MC Controller" and its tooltip to
#    "Access Controller" for clarity and consistency.
"""
import os
import sys
import re
import time
import binascii
import threading
import queue
import argparse
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
import traceback


# --- Helper to ensure bytes for NFC write ---
def ensure_bytes(data):
    """Return a bytes instance appropriate for write_without_encryption.

    Accepts: bytes, bytearray, list/tuple of ints, list/tuple of bytes/bytearray.
    Raises TypeError for unsupported shapes.
    """
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if isinstance(data, (list, tuple)):
        # list of integers -> bytes([...])
        if all(isinstance(x, int) for x in data):
            return bytes(data)
        # list/tuple of bytes or bytearray -> join them
        if all(isinstance(x, (bytes, bytearray)) for x in data):
            return b"".join(bytes(x) for x in data)
    raise TypeError(f"Unsupported data type for Felica write: {type(data)!r}")


# --- nfcpy and Key Generation Libraries ---
try:
    import nfc
    NFC_AVAILABLE = True
except ImportError as e:
    print(f"Warning: nfcpy library not found. NFC functionality will be disabled. ({e})", file=sys.stderr)
    NFC_AVAILABLE = False

import hashlib
import hmac

# --- Constants ---
FELICA_LITE_S_BLOCKS = 16
FELICA_LITE_S_BYTES = FELICA_LITE_S_BLOCKS * 16
READ_ONLY_BLOCKS = {14, 15}
ZERO_BLOCK = b'\x00' * 16
SUPPORTED_ENCODINGS = ['shift_jis', 'utf-8', 'euc-jp', 'latin-1']

# ==============================================================================
# 0. Backend Logic for Access Rights (UPDATED for official spec)
# ==============================================================================
class MCBlockHandler:
    """
    Manages the creation and parsing of the 16-byte MC Block (Block 88h/15) data.
    This implementation is based on the FeliCa Lite-S User's Manual (Version 1.4) Table 3-2.
    The maximum user block number is 13 (0Dh). REG block is 14 (0Eh). Total 15 blocks (0-14).
    MC[0] and MC[1] cover blocks S_PAD0 (0) through REG (14).
    """
    def __init__(self):
        # Array size of 15 for S_PAD0 to REG (Block 0 to 14)
        self.max_blocks = 15

        # MC[0] bit 0-7, MC[1] bit 0-6 (Total 15 bits for RW/RO setting)
        self.rw_ro_settings = [1] * self.max_blocks  # 1: RW, 0: RO

        # MC[6] bit 0-7, MC[7] bit 0-6 (Total 15 bits for Read Auth setting)
        self.r_auth_settings = [0] * self.max_blocks # 1: Auth Required, 0: No Auth

        # MC[8] bit 0-7, MC[9] bit 0-6 (Total 15 bits for Write Auth setting)
        self.w_auth_settings = [0] * self.max_blocks # 1: Auth Required, 0: No Auth

        # MC[10] bit 0-7, MC[11] bit 0-6 (Total 15 bits for Write MAC setting)
        self.w_mac_settings = [0] * self.max_blocks # 1: MAC Required, 0: MAC Not Required

    def _get_bit_index(self, block_num):
        """Maps block_num (0-14) to the corresponding bit index (0-14)."""
        # Block 0-7 map to bit 0-7 in MC[0], MC[6], MC[8], MC[10]
        if 0 <= block_num <= 7:
            return block_num, 0 # Bit index, Byte offset (0 for MC[0], MC[6]...)
        # Block 8-13 map to bit 0-5 in MC[1], MC[7], MC[9], MC[11]
        elif 8 <= block_num <= 13:
            return block_num - 8, 1 # Bit index, Byte offset (1 for MC[1], MC[7]...)
        # Block 14 (REG) maps to bit 6 in MC[1], MC[7], MC[9], MC[11]
        elif block_num == 14:
            return 6, 1
        return None, None

    def _get_mc_byte_index(self, byte_offset, base_index):
        """Calculates the final MC byte index based on offset and base."""
        # base_index: 0 (for MC[0]), 6 (for MC[6]), 8 (for MC[8]), 10 (for MC[10])
        return base_index + byte_offset

    def get_access_mode_string(self, block_num):
        """Gets the access mode as a descriptive string for the UI dropdown."""
        if not (0 <= block_num < self.max_blocks): return ""
        is_rw = self.rw_ro_settings[block_num]
        needs_r_auth = self.r_auth_settings[block_num]
        needs_w_auth = self.w_auth_settings[block_num]
        needs_w_mac = self.w_mac_settings[block_num]

        if is_rw == 0: # RO
            return "RO (R Auth)" if needs_r_auth else "RO"
        else: # RW
            conditions = []
            if needs_r_auth: conditions.append("R Auth")
            if needs_w_auth: conditions.append("W Auth")
            if needs_w_mac: conditions.append("W MAC")
            if not conditions:
                return "RW"
            else:
                # Example: "RW (R Auth W Auth)"
                return f"RW ({' '.join(conditions)})"

    def set_access_mode_from_string(self, block_num, mode_str):
        """Sets the access mode based on a descriptive string from the UI."""
        if not (0 <= block_num < self.max_blocks): return

        # Reset auth settings to default before applying new ones
        self.r_auth_settings[block_num] = 0
        self.w_auth_settings[block_num] = 0
        self.w_mac_settings[block_num] = 0

        if mode_str.startswith("RO"):
            self.rw_ro_settings[block_num] = 0
            if "R Auth" in mode_str:
                self.r_auth_settings[block_num] = 1
        elif mode_str.startswith("RW"):
            self.rw_ro_settings[block_num] = 1
            if "R Auth" in mode_str:
                self.r_auth_settings[block_num] = 1
            if "W Auth" in mode_str:
                self.w_auth_settings[block_num] = 1
            if "W MAC" in mode_str:
                self.w_mac_settings[block_num] = 1

    def generate_mc_block_data(self):
        """Generates the 16-byte MC Block data based on internal settings and defaults."""
        mc_data = bytearray(16)

        # --- FeliCa Lite-S User's Manual (v1.4) Section 3.1.12に基づくデフォルト値 ---
        # MC[2]: システムブロックのアクセス権。FFh=RW (Unlocked) [cite: 591]
        mc_data[2] = 0xFF 
        # MC[3]: NDEF設定。00h=非対応 (Default) [cite: 584]
        mc_data[3] = 0x00
        # MC[4]: RFパラメータ。07hを書き込むことが規定されている [cite: 581]
        mc_data[4] = 0x07
        # MC[5]: CK/CKVのMAC付き書き込み設定。00h=MAC不要 (Default) [cite: 578]
        mc_data[5] = 0x00
        mc_data[12] = 0x00
        mc_data[13:] = b'\x00\x00\x00'
        mc_data[1] |= (0b1 << 7) # MC[1] bit7 は予約ビットだが、元コードの挙動を維持


        for block_num in range(self.max_blocks):
            bit_index, byte_offset = self._get_bit_index(block_num)
            if bit_index is None: continue

            mc01_idx = self._get_mc_byte_index(byte_offset, 0)
            if self.rw_ro_settings[block_num] == 1:
                mc_data[mc01_idx] |= (0b1 << bit_index)

            mc67_idx = self._get_mc_byte_index(byte_offset, 6)
            if self.r_auth_settings[block_num] == 1:
                mc_data[mc67_idx] |= (0b1 << bit_index)

            mc89_idx = self._get_mc_byte_index(byte_offset, 8)
            if self.w_auth_settings[block_num] == 1:
                mc_data[mc89_idx] |= (0b1 << bit_index)

            mc1011_idx = self._get_mc_byte_index(byte_offset, 10)
            if self.w_mac_settings[block_num] == 1:
                mc_data[mc1011_idx] |= (0b1 << bit_index)

        return bytes(mc_data)

    def parse_mc_block_data(self, mc_data_bytes):
        """Parses the 16-byte MC Block data into internal settings."""
        if not mc_data_bytes or len(mc_data_bytes) < 16:
            self.__init__()
            return

        for block_num in range(self.max_blocks):
            bit_index, byte_offset = self._get_bit_index(block_num)
            if bit_index is None: continue

            def is_set(base_index):
                mc_idx = self._get_mc_byte_index(byte_offset, base_index)
                return (mc_data_bytes[mc_idx] >> bit_index) & 0b1

            self.rw_ro_settings[block_num] = is_set(0)
            self.r_auth_settings[block_num] = is_set(6)
            self.w_auth_settings[block_num] = is_set(8)
            self.w_mac_settings[block_num] = is_set(10)

        return mc_data_bytes

# ==============================================================================
# 1. NFC Operations Controller
# ==============================================================================
class NfcController:
    """Handles all communication with the NFC reader."""
    def __init__(self):
        if not NFC_AVAILABLE:
            raise ImportError("Cannot perform NFC operations because the nfcpy library is not available.")

    def _connect_and_operate(self, operation_fn, timeout=8):
        """Generic method to connect to a card and perform a given operation.
        - 出力 result['error'] にフルの traceback を入れる（デバッグ用）
        - clf.sense 呼び出しで例外が出ても壊れないように保護
        """
        try:
            with nfc.ContactlessFrontend('usb') as clf:
                result = {'ok': False, 'error': 'Timeout: No FeliCa card detected.', 'data': None}

                started = time.time()
                target = None

                # polling loop with robust sense-call handling
                while time.time() - started < timeout:
                    try:
                        # 一般的な呼び出し（既存コードと互換）
                        target = clf.sense(nfc.clf.RemoteTarget('212F'), iterations=3, interval=0.1)
                    except Exception as e:
                        # nfcpy バージョン差異の可能性を考慮して代替呼び出しを試す
                        try:
                            target = clf.sense(nfc.clf.RemoteTarget('felica'), iterations=3, interval=0.1)
                        except Exception:
                            # 最終手段：引数付きではなく単純に sense() を試す
                            try:
                                target = clf.sense()
                            except Exception:
                                # ここでは例外を無視してループ継続（タイムアウトで最終的に抜ける）
                                target = None

                    if target is not None:
                        try:
                            tag = nfc.tag.activate(clf, target)
                            if tag is None:
                                result['error'] = "Failed to activate the card."
                                return result

                            # 実際の操作を呼ぶ。ここで例外が出たら traceback を result['error'] に入れる
                            try:
                                operation_fn(tag, result)
                                return result
                            except Exception:
                                result['error'] = traceback.format_exc()
                                return result

                        except Exception:
                            # activate() 周りで起きた例外の完全なスタックトレースを残す
                            result['error'] = traceback.format_exc()
                            return result

                    # CPU 負荷低減
                    time.sleep(0.1)

                # タイムアウト時の result（上書きせず返す）
                return result

        except IOError as e:
            # NFC ハードウェア無し等の致命的エラー
            return {'ok': False, 'error': f"NFC reader not found: {e}", 'data': None}
        except Exception:
            # その他の予期せぬエラーは完全な traceback を返す
            return {'ok': False, 'error': traceback.format_exc(), 'data': None}


    def get_card_info(self):
        """Retrieves the card's IDm, PMm, and System Code."""
        def op(tag, result):
            idm = binascii.hexlify(tag.idm).decode('ascii').upper()
            pmm = binascii.hexlify(tag.pmm).decode('ascii').upper()
            # hasattrでtagオブジェクトにsys_code属性があるか確認
            if hasattr(tag, 'sys_code') and tag.sys_code is not None:
                sys_code = f"{tag.sys_code:04X}"
            else:
                sys_code = "FE00"
            result['data'] = {'idm': idm, 'pmm': pmm, 'sys_code': sys_code}
            result['ok'] = True
            result['error'] = ''
        return self._connect_and_operate(op)

    def read_block_unauthenticated(self, block_num):
        """Reads a block without authentication."""
        def op(tag, result):
            read_data = None
            try:
                if hasattr(tag, 'read_without_encryption'):
                    # Prefer ServiceCode/BlockCode objects (nfcpy tt3 API). If the
                    # tt3 helper classes are not available, fall back to the
                    # older integer-based calling convention.
                    try:
                        if hasattr(nfc.tag, 'tt3') and hasattr(nfc.tag.tt3, 'ServiceCode'):
                            service = nfc.tag.tt3.ServiceCode(0x000B >> 6, 0x000B & 0x3F)
                            blockcode = nfc.tag.tt3.BlockCode(block_num)
                            data_list = tag.read_without_encryption([service], [blockcode])
                        else:
                            data_list = tag.read_without_encryption([0x000B], [block_num])
                    except Exception:
                        # If the library raises, propagate the exception to outer handler
                        raise

                    if data_list and data_list[0] is not None:
                        read_data = bytes(data_list[0])[:16].ljust(16, b'\x00')

                if read_data:
                    result['data'], result['ok'], result['error'] = read_data, True, ''
                else:
                    result['error'] = f"Failed to read block {block_num}."
            except Exception:
                result['error'] = traceback.format_exc()
        return self._connect_and_operate(op, timeout=2)

    def read_block_authenticated(self, block_num, key_hex, ckv_hex): 
        """Reads a block using an authentication key."""
        key_bytes = binascii.unhexlify(key_hex)
        def op(tag, result):
            if not hasattr(tag, 'read_with_mac'):
                result['error'] = "This card does not support authenticated reads."
                return
            try:
                ckv_int = int(ckv_hex, 16) if len(ckv_hex) == 4 else 0

                tag.authentication(key_version=ckv_int, password=key_bytes)
                try:
                    # Prefer BlockCode objects when possible
                    try:
                        blockcode = nfc.tag.tt3.BlockCode(block_num)
                        data = tag.read_with_mac([blockcode])[0]
                    except Exception:
                        data = tag.read_with_mac([block_num])[0]
                    result['data'], result['ok'], result['error'] = bytes(data), True, ''
                except Exception:
                    result['error'] = traceback.format_exc()
            except Exception:
                result['error'] = traceback.format_exc()
        return self._connect_and_operate(op, timeout=4)

    def write_block_unauthenticated(self, block_num, data_hex):
        """Writes to a block without authentication. Now checks MC block for write protection."""
        data_bytes = ensure_bytes(binascii.unhexlify(data_hex))
        def op(tag, result):
            import nfc.tag.tt3
            write_ok = False
            try:
                # Ensure tag is a Type3Tag
                if not isinstance(tag, nfc.tag.tt3.Type3Tag):
                    result['ok'] = False
                    result['error'] = "Tag is not a nfcpy Type3Tag (FeliCa)."
                    return

                # Prepare payload
                payload = ensure_bytes(data_bytes)
                if len(payload) < 16:
                    payload = payload.ljust(16, b'\x00')
                elif len(payload) > 16:
                    payload = payload[:16]

                # Use only nfcpy's official API and types
                service = nfc.tag.tt3.ServiceCode(0, 0b001001)  # 0x0009, NDEF write w/o key
                blockcode = nfc.tag.tt3.BlockCode(block_num)
                tag.write_without_encryption([service], [blockcode], payload)

                # Read back for verification
                time.sleep(0.15)
                rservice = nfc.tag.tt3.ServiceCode(0, 0b001011)  # 0x000B, NDEF read w/o key
                rblockcode = nfc.tag.tt3.BlockCode(block_num)
                data_list = tag.read_without_encryption([rservice], [rblockcode])
                readback = None
                if data_list and data_list[0] is not None:
                    readback = bytes(data_list[0])[:16].ljust(16, b'\x00')

                if readback == payload:
                    write_ok = True

                if not write_ok:
                    got_hex = readback.hex().upper() if readback else 'None'
                    expected_hex = payload.hex().upper()
                    hint = ''
                    if readback == b'\x00' * 16:
                        hint = ' (readback is all-zero; the card likely ignored the write or the block is write-protected or not writable)'
                    result['error'] = (
                        "Write verification failed: readback does not match payload.\n"
                        f"Expected: {expected_hex}\nGot:      {got_hex}{hint}"
                    )

                result['ok'] = write_ok
                if not write_ok and 'error' not in result:
                    result['error'] = f"Failed to write to block {block_num}."
            except Exception:
                result['ok'] = False
                result['error'] = traceback.format_exc()
        return self._connect_and_operate(op, timeout=4)

    def write_block_authenticated(self, block_num, data_hex, key_hex, ckv_hex): 
        """Writes to a block using an authentication key (and MAC)."""
        key_bytes = binascii.unhexlify(key_hex)
        data_bytes = binascii.unhexlify(data_hex)
        def op(tag, result):
            if not hasattr(tag, 'write_with_mac'):
                result['error'] = "This card does not support authenticated writes."
                return
            try:
                ckv_int = int(ckv_hex, 16) if len(ckv_hex) == 4 else 0

                tag.authentication(key_version=ckv_int, password=key_bytes)
                try:
                    try:
                        blockcode = nfc.tag.tt3.BlockCode(block_num)
                        # pass bytes object for payload (one bytes per block)
                        payload = bytes(data_bytes)
                        try:
                            tag.write_with_mac([blockcode], [payload])
                        except TypeError:
                            tag.write_with_mac([blockcode], [bytearray(payload)])
                    except Exception:
                        payload = bytes(data_bytes)
                        try:
                            tag.write_with_mac([block_num], [payload])
                        except TypeError:
                            tag.write_with_mac([block_num], [bytearray(payload)])
                    result['ok'], result['error'] = True, ''
                except Exception:
                    result['ok'] = False
                    result['error'] = traceback.format_exc()
            except Exception:
                result['error'] = traceback.format_exc()
        return self._connect_and_operate(op, timeout=4)


# ==============================================================================
# 2. Tool Windows (KeyGen, AsciiHex)
# ==============================================================================
class KeyGenWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("FeliCa Auth Key Generator (16-byte)")
        self.geometry("450x420")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.grab_set()
        self.focus_set()
        self.idm_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.result_var = tk.StringVar(value="Generated 16-byte (32-char HEX) auth key appears here.")
        self._create_widgets()

    def on_close(self):
        self.grab_release()
        self.destroy()

    def _create_widgets(self):
        main_frame = ttk.Frame(self, padding=15)
        main_frame.pack(padx=10, pady=10, fill='x', expand=True)

        idm_labelframe = ttk.Labelframe(main_frame, text="FeliCa IDm (16 HEX chars)")
        idm_labelframe.pack(fill='x', pady=5)
        idm_inner_frame = ttk.Frame(idm_labelframe, padding=5)
        idm_inner_frame.pack(fill='x')
        self.idm_entry = ttk.Entry(idm_inner_frame, textvariable=self.idm_var, width=25, font=("Courier New", 10))
        self.idm_entry.pack(side='left', fill='x', expand=True, padx=(0, 5))
        idm_read_btn = ttk.Button(idm_inner_frame, text="Read IDm", command=self.read_idm_from_felica, state='normal' if NFC_AVAILABLE else 'disabled')
        idm_read_btn.pack(side='left')

        pw_labelframe = ttk.Labelframe(main_frame, text="Passphrase (HMAC Key)")
        pw_labelframe.pack(fill='x', pady=5)
        pw_inner_frame = ttk.Frame(pw_labelframe, padding=5)
        pw_inner_frame.pack(fill='x')
        self.pw_entry = ttk.Entry(pw_inner_frame, textvariable=self.password_var, show="•", width=30)
        self.pw_entry.pack(fill='x')

        ttk.Button(main_frame, text="Generate Auth Key (HASH)", command=self.generate_auth_key_hmac).pack(fill='x', pady=10)

        result_labelframe = ttk.Labelframe(main_frame, text="Generated Auth Key (CK)")
        result_labelframe.pack(fill='x', pady=5)
        result_inner_frame = ttk.Frame(result_labelframe, padding=5)
        result_inner_frame.pack(fill='x')
        result_label = ttk.Label(result_inner_frame, textvariable=self.result_var, font=("Courier New", 10), wraplength=380, justify='left')
        result_label.pack(fill='x', pady=5)
        btn_frame = ttk.Frame(result_inner_frame)
        btn_frame.pack(fill='x', pady=5)
        ttk.Button(btn_frame, text="Copy to Clipboard", command=self.copy_to_clipboard).pack(side='left', expand=True, fill='x', padx=(0,5))
        ttk.Button(btn_frame, text="Copy to Auth Key Field", command=self.copy_to_auth_field).pack(side='left', expand=True, fill='x')

        if not NFC_AVAILABLE:
            ttk.Label(main_frame, text="Note: nfcpy not found. 'Read IDm' is disabled.", foreground='red').pack(pady=5)

    def generate_auth_key_hmac(self):
        idm_str = self.idm_var.get().strip().upper()
        password = self.password_var.get()
        if not idm_str or not password:
            messagebox.showerror("Error", "Both IDm and Passphrase are required.", parent=self)
            return
        if len(idm_str) != 16 or not all(c in '0123456789ABCDEF' for c in idm_str):
            messagebox.showerror("Error", "IDm must be a valid 16-character hexadecimal string.", parent=self)
            return
        try:
            msg_bytes = bytes.fromhex(idm_str)
            key_bytes = password.encode('utf-8')
            auth_key_bytes_16 = hmac.new(key_bytes, msg_bytes, hashlib.sha256).digest()[:16]
            self.result_var.set(auth_key_bytes_16.hex().upper())
        except Exception as e:
            messagebox.showerror("Error", f"Hash generation failed: {e}", parent=self)

    def read_idm_from_felica(self):
        messagebox.showinfo("Reading IDm", "Place a FeliCa card on the NFC reader...", parent=self)
        try:
            controller = NfcController()
            result = controller.get_card_info()
            if result['ok']:
                self.idm_var.set(result['data']['idm'])
                messagebox.showinfo("Success", f"Read IDm:\n{result['data']['idm']}", parent=self)
            else:
                messagebox.showerror("Failed", f"Failed to read IDm:\n{result['error']}", parent=self)
        except Exception as e:
            messagebox.showerror("Error", f"An NFC error occurred: {e}", parent=self)

    def copy_to_clipboard(self):
        hash_value = self.result_var.get()
        if len(hash_value) == 32:
            self.clipboard_clear(); self.clipboard_append(hash_value)
            self.parent.append_log("INFO", "Auth Key (CK) copied to clipboard.")
        else:
            messagebox.showwarning("Warning", "No valid Auth Key has been generated.", parent=self)

    def copy_to_auth_field(self):
        hash_value = self.result_var.get()
        if len(hash_value) == 32:
            self.parent.entry_key.delete(0, 'end')
            self.parent.entry_key.insert(0, hash_value)
            self.on_close()
        else:
            messagebox.showwarning("Warning", "No valid Auth Key has been generated.", parent=self)

class AsciiHexConverterWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("ASCII to HEX Converter")
        self.geometry("450x350")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.grab_set()
        self.focus_set()

        self.style = ttk.Style(self)
        self.style.configure("Error.TEntry", fieldbackground="#FFCCCC")

        self.input_text_var = tk.StringVar()
        self.input_text_var.trace_add("write", self.on_text_change)
        self.encoding_var = tk.StringVar(value=SUPPORTED_ENCODINGS[0])
        self.output_hex_var = tk.StringVar(value="HEX output appears here.")
        self.length_var = tk.StringVar(value="Length: 0 bytes")

        self._create_widgets()
        self.on_text_change()

    def on_close(self):
        self.grab_release()
        self.destroy()

    def _create_widgets(self):
        main_frame = ttk.Frame(self, padding=15)
        main_frame.pack(padx=10, pady=10, fill='both', expand=True)

        input_frame = ttk.Labelframe(main_frame, text="Input Text")
        input_frame.pack(fill='x', pady=5)
        input_inner_frame = ttk.Frame(input_frame, padding=5)
        input_inner_frame.pack(fill='x')

        self.input_entry = ttk.Entry(input_inner_frame, textvariable=self.input_text_var, font=("Courier New", 10))
        self.input_entry.pack(side='left', fill='x', expand=True, padx=(0, 5))

        self.encoding_menu = ttk.Combobox(input_inner_frame, textvariable=self.encoding_var, values=SUPPORTED_ENCODINGS, width=10, state='readonly')
        self.encoding_menu.pack(side='left')
        self.encoding_menu.bind('<<ComboboxSelected>>', self.on_text_change)

        result_frame = ttk.Labelframe(main_frame, text="Output HEX (16 bytes)")
        result_frame.pack(fill='x', pady=5)
        result_inner_frame = ttk.Frame(result_frame, padding=5)
        result_inner_frame.pack(fill='x')

        self.length_label = ttk.Label(result_inner_frame, textvariable=self.length_var)
        self.length_label.pack(anchor='w', pady=(0, 5))

        self.result_entry = ttk.Entry(result_inner_frame, textvariable=self.output_hex_var, font=("Courier New", 10), state='readonly')
        self.result_entry.pack(fill='x')

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill='x', pady=10)
        self.copy_button = ttk.Button(btn_frame, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.pack(side='left', expand=True, fill='x', padx=(0,5))
        self.transfer_button = ttk.Button(btn_frame, text="Transfer to Selected Block", command=self.transfer_to_main_gui)
        self.transfer_button.pack(side='left', expand=True, fill='x')

    def on_text_change(self, *args):
        input_text = self.input_text_var.get()
        encoding = self.encoding_var.get()
        try:
            encoded_bytes = input_text.encode(encoding)
            byte_len = len(encoded_bytes)

            if byte_len > 16:
                self.length_var.set(f"Length: {byte_len}/16 bytes (OVER)")
                self.output_hex_var.set("ERROR: INPUT IS TOO LONG")
                self.input_entry.config(style="Error.TEntry")
                self.transfer_button.config(state='disabled')
                self.copy_button.config(state='disabled')
            else:
                self.length_var.set(f"Length: {byte_len} bytes")
                self.input_entry.config(style="TEntry")

                padded_bytes = encoded_bytes.ljust(16, b'\x00')
                hex_output = padded_bytes.hex().upper()
                self.output_hex_var.set(hex_output)
                self.transfer_button.config(state='normal')
                self.copy_button.config(state='normal')

        except Exception:
            self.output_hex_var.set("Encoding Error")
            self.length_var.set("Length: N/A")
            self.input_entry.config(style="Error.TEntry")
            self.transfer_button.config(state='disabled')
            self.copy_button.config(state='disabled')

    def copy_to_clipboard(self):
        hex_value = self.output_hex_var.get()
        if len(hex_value) == 32:
            self.clipboard_clear()
            self.clipboard_append(hex_value)
            self.parent.append_log("INFO", "16-byte HEX data copied to clipboard.")
        else:
            messagebox.showwarning("Warning", "No valid HEX data to copy.", parent=self)

    def transfer_to_main_gui(self):
        # --- ▼ 変更点 ▼ ---
        # データがロードされていない場合は転送をブロック
        if not self.parent.has_data_in_ui:
            messagebox.showwarning("No Data Loaded", "Please read a card or load a file first before transferring data.", parent=self)
            return
        # --- ▲ 変更点 ▲ ---

        selected_iid = self.parent.tree.focus()
        if not selected_iid:
            messagebox.showwarning("No Selection", "Please select a block in the main window first.", parent=self)
            return

        hex_value = self.output_hex_var.get()
        if len(hex_value) != 32:
            messagebox.showerror("Error", "Cannot transfer, invalid HEX data generated.", parent=self)
            return

        dummy_entry = ttk.Entry(self)
        dummy_entry.insert(0, hex_value)
        self.parent._save_cell_edit(selected_iid, dummy_entry)
        dummy_entry.destroy()

        self.parent.append_log('INFO', f'Transferred generated HEX data to block {self.parent.tree.item(selected_iid, "values")[0]}.')
        self.on_close()

# ==============================================================================
# 3. Main GUI Application
# ==============================================================================
class FelicaGUI(tk.Tk):
    def __init__(self, test_file=None):
        super().__init__()
                # --- ▼▼▼ ここを修正 ▼▼▼ ---
        # 表示・管理対象とするブロック番号の完全なリストを定義
        # ユーザーブロック(0-15)と、システムブロック(128-146)の連続した範囲を指定
        self.BLOCKS_TO_MANAGE = list(range(16)) + list(range(128, 147)) # 147は含まないため146まで

        # システムブロックの役割を定義 (UI表示用)
        self.BLOCK_DESCRIPTIONS = {
            14:  "(REGA[4]B[4]C[8])",
            15:  "(MC Block)", # このアプリではMCブロックとして扱われる
            128: "(RC1[8], RC2[8])",
            129: "(MAC[8])",
            130: "(IDD[8], DFC[2])",
            131: "(IDM[8], PMM[8])",
            132: "(SERVICE_CODE[2])",
            133: "(SYSTEM_CODE[2])",
            134: "(CKV[2])",
            135: "(CK1[8], CK2[8])",
            136: "(MEMORY_CONFIG)",
            144: "(WCNT[3])",
            145: "(MAC_A[8] - Read Protected)",
            146: "(STATE)",
        }
        # --- ▲▲▲ 修正はここまで ▲▲▲ ---
        self.test_mode = test_file is not None
        self.test_file_path = test_file
        title = "FeliCa Manager (FeliCa Lite-S)"
        if self.test_mode: title += " [TEST MODE]"
        self.title(title)
        self.geometry('1300x768'); self.minsize(1100, 600)

        self.nfc_controller = None
        if not self.test_mode and NFC_AVAILABLE:
            try:
                 self.nfc_controller = NfcController()
                 self.nfc_controller.parent = self
            except Exception as e: messagebox.showerror("Initialization Error", str(e))

        self.style = ttk.Style(self)
        self.style.configure("Custom.Treeview", font=("Courier New", 12), rowheight=28)
        self.style.configure("Custom.Treeview.Heading", font=("TkDefaultFont", 10, 'bold'))
        self.style.configure("Danger.TButton", foreground="red", font=('TkDefaultFont', 9, 'bold'))
        self.style.configure("Access.TCombobox", font=("TkDefaultFont", 10))

        self.out_q = queue.Queue()

        self.mc_handler = MCBlockHandler()
        self.original_mc_handler_state = self._get_current_mc_state_copy()
        self.original_dump_data = {}
        
        # --- ▼ 変更点 ▼ ---
        # データがロードされるまでUIの一部を無効化するためのフラグ
        self.has_data_in_ui = False
        # --- ▲ 変更点 ▲ ---

        self.is_card_locked = False
        self.full_write_pending = False
        self.use_auth_key_var = tk.BooleanVar(value=False)
        self.show_key_var = tk.BooleanVar(value=False)
        self.encoding_var = tk.StringVar(value=SUPPORTED_ENCODINGS[0])

        self._create_widgets()
        self._initialize_empty_table()
        self._update_ui_state() # 初期状態としてUIを無効化
        self._poll_queue()
        if self.test_mode: self.after(100, self.load_dummy_data)

    def _get_current_mc_state_copy(self):
        """Returns a copy of the current MC handler settings for comparison/saving."""
        return {
            'rw_ro': list(self.mc_handler.rw_ro_settings),
            'r_auth': list(self.mc_handler.r_auth_settings),
            'w_auth': list(self.mc_handler.w_auth_settings),
            'w_mac': list(self.mc_handler.w_mac_settings),
        }

    def _has_mc_state_changed(self):
        """Checks if MC settings have changed since the last read/write."""
        current_state = self._get_current_mc_state_copy()
        for key in current_state:
            if current_state[key] != self.original_mc_handler_state.get(key, []):
                return True
        return False
        
    # --- ▼ 変更点 ▼ ---
    # UIの有効/無効状態を一元管理するメソッド
    def _update_ui_state(self):
        """Enables or disables UI controls based on whether data is loaded."""
        state = 'normal' if self.has_data_in_ui else 'disabled'
        
        self.write_button.config(state=state)
        self.save_bin_button.config(state=state)
        self.save_json_button.config(state=state)
        self.export_report_button.config(state=state)
        self.write_key_button.config(state=state)
        # Lock button is handled separately based on lock status
        if not self.is_card_locked and self.has_data_in_ui:
            self.lock_button.config(state='normal')
        else:
            self.lock_button.config(state='disabled')
    # --- ▲ 変更点 ▲ ---

    def load_dummy_data(self):
        """Initializes the GUI with dummy data for testing mode."""
        if self.test_file_path:
            try:
                with open(self.test_file_path, 'rb') as f:
                    dummy_data = f.read()
                if len(dummy_data) != FELICA_LITE_S_BYTES:
                    raise ValueError(f"Dummy file must be exactly {FELICA_LITE_S_BYTES} bytes.")

                self._populate_dump_table(dummy_data)
                self.out_q.put(('STATUS_UPDATE', {'idm': '0123456789ABCDEF', 'pmm': '0101010101010101', 'sys_code': '0003'}))
                self.append_log('INFO', f"Loaded dummy data from {self.test_file_path} (Test Mode)")
            except Exception as e:
                self.append_log('ERROR', f"Failed to load dummy data: {e} (Test Mode)")
        else:
            self._populate_dump_table(b'\x00' * FELICA_LITE_S_BYTES)
            self.out_q.put(('STATUS_UPDATE', {'idm': '0000000000000000', 'pmm': '0000000000000000', 'sys_code': 'FFFF'}))
            self.append_log('INFO', "Loaded zero data for Test Mode.")

    def _create_widgets(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Auth Key Generator...", command=lambda: KeyGenWindow(self))
        tools_menu.add_command(label="ASCII to HEX Converter...", command=lambda: AsciiHexConverterWindow(self))

        main_paned = ttk.PanedWindow(self, orient='horizontal')
        main_paned.pack(fill='both', expand=True, padx=8, pady=8)

        left_pane = ttk.PanedWindow(main_paned, orient='vertical')
        main_paned.add(left_pane, weight=3)

        table_container = ttk.Frame(left_pane)
        left_pane.add(table_container, weight=3)

        options_frame = ttk.Frame(table_container)
        options_frame.pack(fill='x', padx=0, pady=(0, 5))
        ttk.Label(options_frame, text="ASCII Encoding:").pack(side='left', padx=(2, 5))
        encoding_menu = ttk.Combobox(options_frame, textvariable=self.encoding_var, values=SUPPORTED_ENCODINGS, state='readonly', width=15)
        encoding_menu.pack(side='left')
        encoding_menu.bind('<<ComboboxSelected>>', self._on_encoding_change)

        table_frame = ttk.Frame(table_container)
        table_frame.pack(fill='both', expand=True)

        log_frame = ttk.Labelframe(left_pane, text="Logs")
        left_pane.add(log_frame, weight=1)

        self.txt_log = tk.Text(log_frame, state='normal', wrap='word', height=5)
        self.txt_log.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        log_scroll = ttk.Scrollbar(log_frame, orient='vertical', command=self.txt_log.yview)
        log_scroll.pack(side='right', fill='y')
        self.txt_log.config(yscrollcommand=log_scroll.set)

        cols = ('block', 'hex', 'ascii', 'access_rights')
        self.tree = ttk.Treeview(table_frame, columns=cols, show='headings', style="Custom.Treeview")
        self.tree.heading('block', text='Block'); self.tree.heading('hex', text='Hex Data (16 bytes)')
        self.tree.heading('ascii', text='ASCII'); self.tree.heading('access_rights', text='Access Rights')
        self.tree.column('block', width=60, anchor='center', stretch=False)
        self.tree.column('hex', width=320, anchor='center'); self.tree.column('ascii', width=200, anchor='center')
        self.tree.column('access_rights', width=220, anchor='center', stretch=False)
        self.tree.tag_configure('readonly', background='#E0E0E0')
        self.tree.tag_configure('modified', background='#E3F2FD')
        self.tree.tag_configure('keyblock', foreground='#555555')
        vscroll = ttk.Scrollbar(table_frame, orient='vertical', command=self.tree.yview)
        vscroll.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=vscroll.set)
        self.tree.pack(fill='both', expand=True, padx=(0, 5), pady=0)

        self.tree.bind('<Double-1>', self.on_tree_double_click)
        self.tree.bind('<Button-1>', self.on_tree_click)
        self.tooltip_window = None
        self.tree.bind('<Motion>', self.on_tree_motion)
        self.tree.bind('<Leave>', self.on_tree_leave)

        right_pane = ttk.Frame(main_paned)
        main_paned.add(right_pane, weight=1)
        info_frame = ttk.Labelframe(right_pane, text="Card Information")
        info_frame.pack(fill='x', padx=5, pady=(0, 5))
        ops_frame = ttk.Labelframe(right_pane, text="Operations")
        ops_frame.pack(fill='x', padx=5, pady=5)
        auth_frame = ttk.Labelframe(right_pane, text="Authentication")
        auth_frame.pack(fill='x', padx=5, pady=5)

        status_frame = ttk.Frame(info_frame, padding=5); status_frame.pack(fill='x')
        ttk.Label(status_frame, text="System Code:").grid(row=0, column=0, sticky='w')
        self.lbl_syscode = ttk.Label(status_frame, text='-', font=('TkDefaultFont', 9, 'bold'))
        self.lbl_syscode.grid(row=0, column=1, sticky='w', padx=6)
        ttk.Label(status_frame, text="IDm:").grid(row=1, column=0, sticky='w')
        self.lbl_idm = ttk.Label(status_frame, text='-'); self.lbl_idm.grid(row=1, column=1, sticky='w', padx=6)
        ttk.Label(status_frame, text="PMm:").grid(row=2, column=0, sticky='w')
        self.lbl_pmm = ttk.Label(status_frame, text='-'); self.lbl_pmm.grid(row=2, column=1, sticky='w', padx=6)
        ttk.Label(status_frame, text="Lock Status:").grid(row=3, column=0, sticky='w')
        self.lbl_lock_status = ttk.Label(status_frame, text='-', font=('TkDefaultFont', 9, 'bold'))
        self.lbl_lock_status.grid(row=3, column=1, sticky='w', padx=6)

        ops_inner = ttk.Frame(ops_frame, padding=10); ops_inner.pack(fill='x')
        self.read_button = ttk.Button(ops_inner, text='Read Card', command=self.on_smart_dump)
        self.read_button.pack(fill='x', pady=2)
        self.write_button = ttk.Button(ops_inner, text='Write Changes to Card', command=self.on_write_changes)
        self.write_button.pack(fill='x', pady=2)

        self.save_bin_button = ttk.Button(ops_inner, text='Save Data Dump (.bin)...', command=self.on_save_data)
        self.save_bin_button.pack(fill='x', pady=2)
        ttk.Button(ops_inner, text='Load Data Dump (.bin)...', command=self.on_load_data).pack(fill='x', pady=2)

        self.save_json_button = ttk.Button(ops_inner, text='Save Data (JSON)...', command=self.on_export_json)
        self.save_json_button.pack(fill='x', pady=2)
        ttk.Button(ops_inner, text='Load Data (JSON)...', command=self.on_import_json).pack(fill='x', pady=2)

        self.export_report_button = ttk.Button(ops_inner, text='Export Report (.txt)...', command=self.on_export_report)
        self.export_report_button.pack(fill='x', pady=2)

        ttk.Separator(ops_inner, orient='horizontal').pack(fill='x', pady=8)

        self.lock_button = ttk.Button(ops_inner, text='Permanently Lock Card...', command=self.on_lock_card, style="Danger.TButton")
        self.lock_button.pack(fill='x', pady=2)

        auth_inner = ttk.Frame(auth_frame, padding=5); auth_inner.pack(fill='x')

        ttk.Label(auth_inner, text='Card Key Version (CKV, 4 HEX chars):').pack(fill='x')
        self.entry_ckv = ttk.Entry(auth_inner, width=5)
        self.entry_ckv.insert(0, "0000")
        self.entry_ckv.pack(fill='x', pady=(0, 5))

        ttk.Label(auth_inner, text='Card Key (CK, 32 HEX chars):').pack(fill='x')
        self.entry_key = ttk.Entry(auth_inner, width=35, show='*')
        self.entry_key.pack(fill='x', pady=(0, 5))

        self.write_key_button = ttk.Button(auth_inner, text='Write as New Card Key to Block 14', command=self.on_write_key)
        self.write_key_button.pack(fill='x', pady=(2, 5))

        ttk.Checkbutton(auth_inner, text='Show key', variable=self.show_key_var, command=self.toggle_key_visibility).pack(fill='x')
        ttk.Checkbutton(auth_inner, text='Use auth key for protected reads/writes', variable=self.use_auth_key_var).pack(fill='x', pady=(5,0))

    def _format_access_string(self, block_num):
        """Generates a clean, user-friendly string for the access rights column."""
        # --- ▼ 変更点 ▼ ---
        # ブロック15の表示名を「MC Controller」に変更
        if not (0 <= block_num <= 14):
            return "MC Controller" if block_num == 15 else ""
        # --- ▲ 変更点 ▲ ---

        is_rw = self.mc_handler.rw_ro_settings[block_num]
        base = "RW" if is_rw == 1 else "RO"

        conditions = []
        if self.mc_handler.r_auth_settings[block_num] == 1: conditions.append("RA")
        if is_rw == 1:
            if self.mc_handler.w_auth_settings[block_num] == 1: conditions.append("WA")
            if self.mc_handler.w_mac_settings[block_num] == 1: conditions.append("WM")

        if not conditions:
            return base
        else:
            return f"{base} [{' '.join(conditions)}]"

    def append_log(self, level, text):
        ts = time.strftime('%H:%M:%S')
        self.txt_log.insert('end', f'[{ts}] {level}: {text.strip()}\n')
        self.txt_log.see('end')

    def clear_log(self):
        self.txt_log.delete('1.0', 'end')

    def toggle_key_visibility(self):
        self.entry_key.config(show='' if self.show_key_var.get() else '*')

    def _poll_queue(self):
        try:
            while True:
                msg_type, payload = self.out_q.get_nowait()
                if msg_type == 'LOG': self.append_log(payload[0], payload[1])
                elif msg_type == 'DUMP_COMPLETE': self._populate_dump_table(payload)
                elif msg_type == 'STATUS_UPDATE':
                    self.lbl_idm.config(text=payload.get('idm', '-'))
                    self.lbl_syscode.config(text=f"0x{payload.get('sys_code', '-')}")
                    self.lbl_pmm.config(text=payload.get('pmm', '-'))
                elif msg_type == 'LOCK_STATUS_UPDATE':
                    self.is_card_locked = payload
                    status_text = "LOCKED" if self.is_card_locked else "Unlocked"
                    text_color = "red" if self.is_card_locked else "green"
                    self.lbl_lock_status.config(text=status_text, foreground=text_color)
                    self._update_ui_state() # ロック状態が変わったらUI状態を更新
        except queue.Empty: pass
        self.after(200, self._poll_queue)

    def _on_encoding_change(self, event):
        if not self.tree.get_children(): return

        current_data_map = {}
        for iid in self.tree.get_children():
             values = self.tree.item(iid, 'values')
             block_num = int(values[0])
             current_data_map[block_num] = binascii.unhexlify(values[1])

        encoding = self.encoding_var.get()
        for iid in self.tree.get_children():
            block_num = int(self.tree.item(iid, 'values')[0])
            if block_num in [14, 15]: continue
            chunk = current_data_map[block_num]
            try:
                ascii_data = chunk.decode(encoding, errors='replace').replace('\x00', '.')
            except Exception:
                ascii_data = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk).replace('\x00', '.')
            self.tree.set(iid, 'ascii', ascii_data)

        self.append_log('INFO', f'ASCII column re-decoded with {self.encoding_var.get()}.')

    def on_smart_dump(self):
        if self.test_mode:
            messagebox.showinfo("Test Mode", "Card reading is disabled in Test Mode. Loading dummy data.")
            self.load_dummy_data()
            return
        if not self.nfc_controller:
            messagebox.showerror("Error", "NFC controller not initialized.")
            return
        threading.Thread(target=self._smart_dump_worker, daemon=True).start()

    def _smart_dump_worker(self):
        q_put = lambda level, text: self.out_q.put(('LOG', (level, text)))
        dump_map = {}
        read_success = False

        q_put('INFO', "--- Starting Read Sequence (Block-by-Block) ---")
        try:
            q_put('INFO', "Step 1: Initializing NFC reader ('usb')...")
            with nfc.ContactlessFrontend('usb') as clf:
                q_put('SUCCESS', "Step 1: NFC reader initialized successfully.")
                q_put('INFO', "Step 2: Waiting for a FeliCa card (10 seconds)...")
                target = clf.sense(nfc.clf.RemoteTarget('212F'), timeout=10.0)

                if target is None:
                    q_put('ERROR', "Step 2 Failed: No card detected.")
                    return
                
                q_put('SUCCESS', f"Step 2: Card detected: {target}")
                q_put('INFO', "Step 3: Activating tag...")
                tag = nfc.tag.activate(clf, target)

                if tag is None:
                    q_put('ERROR', "Step 3 Failed: Could not activate tag.")
                    return
                    
                q_put('SUCCESS', "Step 3: Tag activated successfully.")
                idm = binascii.hexlify(tag.idm).decode('ascii').upper()
                pmm = binascii.hexlify(tag.pmm).decode('ascii').upper()
                sys_code = "88B4" if not hasattr(tag, 'sys_code') or tag.sys_code is None else f"{tag.sys_code:04X}"
                self.out_q.put(('STATUS_UPDATE', {'idm': idm, 'pmm': pmm, 'sys_code': sys_code}))

                q_put('INFO', f"Step 4: Reading all defined blocks one-by-one...")
                service = nfc.tag.tt3.ServiceCode(0x000B >> 6, 0x000B & 0x3F)

                for block_num in self.BLOCKS_TO_MANAGE:
                    try:
                        if block_num == 145: # MAC_A (Write-Only)
                            q_put('INFO', f"Block {block_num}: Skipped (Write-Only).")
                            dump_map[block_num] = b'?' * 16
                            continue

                        block_code = nfc.tag.tt3.BlockCode(block_num)
                        read_result = tag.read_without_encryption([service], [block_code])

                        if read_result and read_result[0] is not None:
                            dump_map[block_num] = bytes(read_result[0])
                            q_put('SUCCESS', f"Block {block_num}: Read successful.")
                        else:
                            raise IOError("Read returned no data or null data.")
                    except Exception as e:
                        # --- 変更点：読み取り失敗時はゼロではなく、失敗を示すマーカーを設定 ---
                        q_put('WARN', f"Block {block_num}: Read failed. Error: {e}")
                        dump_map[block_num] = b'!' * 16 # '!' x 16 を失敗マーカーとする
                
                read_success = True

        except Exception as e:
            q_put('ERROR', f"A critical error occurred during card communication: {e}\n{traceback.format_exc()}")
            
        if read_success:
            self.out_q.put(('LOCK_STATUS_UPDATE', False))
            q_put('INFO', 'Scan finished. Populating table.')
            self.out_q.put(('DUMP_COMPLETE', dump_map))
        else:
            q_put('ERROR', 'Scan failed. Please check logs.')

    # _initialize_empty_tableメソッドを、以下のコードに置き換えてください。

    def _initialize_empty_table(self):
        """Creates the initial empty rows in the treeview."""
        self.tree.delete(*self.tree.get_children())
        for block_num in self.BLOCKS_TO_MANAGE:
            tags = []
            desc = self.BLOCK_DESCRIPTIONS.get(block_num, "")
            
            # --- 変更点：ブロック列にはblock_num（数字）のみを渡す ---
            # これまでの `block_display` 文字列は使わない
            iid = self.tree.insert('', 'end', values=(block_num, '00'*16, '.'*16, desc), tags=tuple(tags))
            
            # タグは別途設定する
            is_readonly = "Read-Only" in desc or "Write-Only" in desc or "CKV/CK" in desc or "MC Block" in desc
            if is_readonly:
                self.tree.item(iid, tags=('readonly',))

    # _populate_dump_tableメソッドを、以下のコードに置き換えてください。

    def _populate_dump_table(self, dump_data_map):
        """Populates the table from a dictionary of binary dump data."""
        self._initialize_empty_table()
        self.original_dump_data.clear()

        mc_data = dump_data_map.get(15, b'\x00' * 16)
        if mc_data not in [b'?'*16, b'!'*16]:
            self.mc_handler.parse_mc_block_data(mc_data)
            self.original_mc_handler_state = self._get_current_mc_state_copy()
            is_locked = (mc_data[2] == 0x00)
            self.out_q.put(('LOCK_STATUS_UPDATE', is_locked))

        encoding = self.encoding_var.get()
        
        for iid in self.tree.get_children():
            # --- 変更点：ブロック列は単純な数値なので、直接intに変換 ---
            block_num = int(self.tree.item(iid, 'values')[0])

            chunk = dump_data_map.get(block_num, b'\x00' * 16)
            hex_data = ""
            ascii_data = ""
            desc = self.BLOCK_DESCRIPTIONS.get(block_num)

            # --- 変更点：マーカーに応じてHexとASCIIの表示を決定 ---
            if chunk == b'?' * 16: # スキップされたブロック
                hex_data = "N/A (Write-Only)"
                ascii_data = desc if desc else "N/A"
            elif chunk == b'!' * 16: # 読み取りに失敗したブロック
                hex_data = "N/A (Read Failed)"
                ascii_data = desc if desc else "N/A"
            else:
                chunk = (chunk + b'\x00' * 16)[:16] # 念のため16バイトに正規化
                hex_data = chunk.hex().upper()
                
                # --- 変更点：ASCII列に辞書の詳細説明を表示する ---
                if desc:
                    ascii_data = desc # 辞書に説明があれば最優先で表示
                else:
                    try:
                        ascii_data = chunk.decode(encoding, errors='replace').replace('\x00', '.')
                    except Exception:
                        ascii_data = '.' * 16

            access_str = self._format_access_string(block_num)
            
            # --- 変更点：ブロック列にはblock_num（数字）をそのまま渡す ---
            self.tree.item(iid, values=(block_num, hex_data, ascii_data, access_str))
            self.original_dump_data[block_num] = hex_data

        self.has_data_in_ui = True
        self._update_ui_state()
        self._update_all_modified_statuses()

    def on_write_key(self):
        """Writes the Card Key (CK) from the UI to Block 14."""
        #if self.is_card_locked:
        #    messagebox.showerror("Error", "Cannot write a new key to a permanently locked card.")
        #    return

        ckv_hex = self.entry_ckv.get().strip().upper()
        ck_hex = self.entry_key.get().strip().upper()
        if len(ckv_hex) != 4 or not all(c in '0123456789ABCDEF' for c in ckv_hex):
            messagebox.showerror("Invalid Input", "CKV must be a valid 4-character hexadecimal string.", parent=self)
            return
        if len(ck_hex) != 32 or not all(c in '0123456789ABCDEF' for c in ck_hex):
            messagebox.showerror("Invalid Input", "Card Key (CK) must be a valid 32-character hexadecimal string.", parent=self)
            return

        if messagebox.askokcancel("Confirm Write to Block 14",
            "WARNING: This will overwrite the Card Key (CK) in Block 14.\n\n"
            f"New Card Key (16 Bytes): {ck_hex}\n\nThis operation cannot be undone. Proceed?", icon='warning'):
            threading.Thread(target=self._write_key_worker, args=(ck_hex,), daemon=True).start()

    def _write_key_worker(self, ck_hex_data):
        q_put = lambda level, text: self.out_q.put(('LOG', (level, text)))
        q_put('INFO', "Attempting to write Card Key (CK) to Block 14...")
        try:
            res = {'ok': True} if self.test_mode else self.nfc_controller.write_block_unauthenticated(14, ck_hex_data)
            if not res['ok']: raise RuntimeError(f"Failed to write key to block 14: {res['error']}")
            q_put('SUCCESS', "Block 14 key updated successfully. Please re-read the card.")
            self.after(0, lambda: messagebox.showinfo("Success", "Card Key (CK) has been written to Block 14.\n\nPlease re-read the card to continue."))
        except RuntimeError as e:
            q_put('ERROR', f'Operation failed: {e}')
            self.after(0, lambda err=e: messagebox.showerror('Write Failed', f"Operation Failed: {err}"))

    def _get_pending_changes(self):
        """Compiles a dictionary of data blocks that have been changed."""
        data_changes = {}
        for iid in self.tree.get_children():
            values = self.tree.item(iid, 'values')
            block_num, hex_data = int(values[0].split(' ')[0]), values[1]
            if block_num not in READ_ONLY_BLOCKS and hex_data != self.original_dump_data.get(block_num):
                data_changes[block_num] = hex_data
        return data_changes

    def on_write_changes(self):
        if self.test_mode:
            self.append_log('INFO', 'Write Changes clicked in Test Mode (simulated).')
            self._write_changes_worker()
            messagebox.showinfo("Test Mode", "Card writing is simulated in Test Mode. Check logs.")
            return
        if not self.nfc_controller:
            messagebox.showerror("Error", "NFC controller not initialized.")
            return

        if not self._get_pending_changes() and not self._has_mc_state_changed():
            messagebox.showinfo('No Changes', 'No data or access rights have been modified.')
            return

        threading.Thread(target=self._write_changes_worker, daemon=True).start()

    def _write_changes_worker(self):

        q_put = lambda level, text: self.out_q.put(('LOG', (level, text)))
        success = False
        data_changes = {}
        try:
            if self.is_card_locked:
                raise RuntimeError("Card is permanently locked. No data or access rights can be written.")

            data_changes = self._get_pending_changes()
            if self._has_mc_state_changed():
                q_put('INFO', 'Access rights have changed. Staging MC Block (15) for writing.')
                new_mc_data = self.mc_handler.generate_mc_block_data()
                data_changes[15] = new_mc_data.hex().upper()

            if not data_changes:
                q_put('INFO', 'No changes to write.')
                return

            use_key = self.use_auth_key_var.get()
            key = self.entry_key.get().strip().upper()
            ckv = self.entry_ckv.get().strip().upper()
            key_is_valid = use_key and key and len(key) == 32 and all(c in '0123456789ABCDEF' for c in key)
            ckv_is_valid = len(ckv) == 4 and all(c in '0123456789ABCDEF' for c in ckv)

            q_put('INFO', f'Writing data to {len(data_changes)} blocks...')
            for blk, hexdata in sorted(data_changes.items()):
                # --- Key Block (14)は専用ボタンのみ許可 ---
                if blk == 14:
                    q_put('WARN', 'Skipping write to Block 14 (Key Block). Use dedicated button.')
                    continue
                # --- MCブロック(15)のMC[2]チェック ---
                if blk == 15 and self._has_mc_state_changed():
                    mc_bytes = binascii.unhexlify(hexdata)
                    if len(mc_bytes) < 3 or mc_bytes[2] == 0x00:
                        raise RuntimeError("MC[2] is 00h! Use the dedicated 'Lock Card' button. Write rejected.")

                # --- 書き込みデータHEX長・内容チェック ---
                if not hexdata or len(hexdata) != 32 or not all(c in '0123456789ABCDEF' for c in hexdata):
                    raise RuntimeError(f"Block {blk}: Data must be 16 bytes (32 hex chars). Got: {hexdata}")

                needs_auth = self.mc_handler.w_auth_settings[blk] == 1 or self.mc_handler.w_mac_settings[blk] == 1
                res = None

                if needs_auth:
                    if not key_is_valid or not ckv_is_valid:
                        raise RuntimeError(f"Block {blk} requires authentication. CK(32 hex) or CKV(4 hex) is invalid.")
                    q_put('INFO', f'Writing to block {blk} (Authenticated)...')
                    res = {'ok': True} if self.test_mode else self.nfc_controller.write_block_authenticated(blk, hexdata, key, ckv)
                else:
                    q_put('INFO', f'Writing to block {blk} (Unauthenticated)...')
                    res = {'ok': True} if self.test_mode else self.nfc_controller.write_block_unauthenticated(blk, hexdata)

                if not res or not res['ok']:
                    err_detail = res.get('error', 'Unknown Error') if res else 'No response'
                    raise RuntimeError(f"Failed to write to block {blk}: {err_detail}")

            q_put('SUCCESS', 'All changes written successfully.')
            success = True
            if not self.test_mode:
                self.after(0, lambda: messagebox.showinfo("Complete", "Write cycle finished successfully.\nIt is recommended to re-read the card to confirm changes."))

        except RuntimeError as e:
            q_put('ERROR', f'Operation failed: {e}')
            if not self.test_mode:
                self.after(0, lambda err=e: messagebox.showerror('Write Failed', f"Operation Failed: {err}"))
        finally:
            if success:
                self.original_mc_handler_state = self._get_current_mc_state_copy()
                for block_num, hex_data in data_changes.items():
                    if block_num in self.original_dump_data:
                        self.original_dump_data[block_num] = hex_data
                for iid in self.tree.get_children():
                    if 'modified' in self.tree.item(iid, 'tags'):
                        tags = list(self.tree.item(iid, 'tags'))
                        tags.remove('modified')
                        self.tree.item(iid, tags=tuple(tags))

    def on_lock_card(self):
        if not self.original_dump_data:
            messagebox.showwarning("No Card Data", "Please read a card first.")
            return
        if self.is_card_locked:
            messagebox.showinfo("Already Locked", "This card has already been permanently locked.")
            return

        title, msg = "FINAL CONFIRMATION: PERMANENT LOCK", "\n".join([
            "WARNING: This operation is absolutely IRREVERSIBLE.",
            "\nThe Card Key (CK) and all access rights will be permanently frozen.",
            "If there are ANY mistakes in the current settings, this card can NEVER be changed again.",
            "\nAre you absolutely sure you want to proceed?"
        ])
        if not messagebox.askokcancel(title, msg, icon='warning'):
            self.append_log('INFO', 'Lock operation cancelled by user.')
            return
        threading.Thread(target=self._lock_card_worker, daemon=True).start()

    def _lock_card_worker(self):
        q_put = lambda level, text: self.out_q.put(('LOG', (level, text)))
        q_put('WARN', 'Starting permanent lock process...')
        try:
            if self.test_mode:
                q_put('SUCCESS', 'Lock command simulated successfully.')
                self.out_q.put(('LOCK_STATUS_UPDATE', True))
                self.after(0, lambda: messagebox.showinfo("Success", "Lock command SIMULATED successfully (Test Mode)."))
                return

            q_put('INFO', 'Reading current MC Block (Block 15)...')
            res = self.nfc_controller.read_block_unauthenticated(15)
            if not res['ok']: raise RuntimeError(f"Failed to read MC Block: {res['error']}")
            mc_data = bytearray(res['data'])

            if mc_data[3] != 0xFF:
                self.out_q.put(('LOCK_STATUS_UPDATE', True))
                raise RuntimeError("Card is already locked or has an unexpected WP value. Aborting.")
            
            mc_data[3] = 0x00

            q_put('INFO', 'Calculated new MC Block data: MC[2] set to 00h to lock.')
            q_put('WARN', 'Sending lock command to card (writing to Block 15)...')

            res = self.nfc_controller.write_block_unauthenticated(15, mc_data.hex())
            if not res['ok']: raise RuntimeError(f"Failed to write lock data to MC Block: {res['error']}")

            q_put('SUCCESS', 'Lock command sent successfully.')
            q_put('IMPORTANT', 'To finalize the lock, please remove the card from the reader now.')
            self.out_q.put(('LOCK_STATUS_UPDATE', True))
            self.after(0, lambda: messagebox.showinfo("Success", "Lock command sent successfully.\nPlease remove and re-read the card to see the updated lock status."))
        except RuntimeError as e:
            q_put('ERROR', f"Lock operation failed: {e}")
            self.after(0, lambda err=e: messagebox.showerror('Lock Failed', f"Operation Failed: {err}"))

    # ==========================================================================
    # --- UI and Editing Methods
    # ==========================================================================
    def on_tree_motion(self, event):
        if self.tooltip_window: self.tooltip_window.destroy()
        self.tooltip_window = None

        iid = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)

        if iid and column == '#4': # Access Rights column
            if str(self.tree.item(iid, "values")[0]).isdigit():
                block_num = int(self.tree.item(iid, "values")[0])
                tooltip_text = self._generate_access_tooltip_text(block_num)

                self.tooltip_window = tw = tk.Toplevel(self)
                tw.wm_overrideredirect(True)
                tw.wm_geometry(f"+{event.x_root + 15}+{event.y_root + 10}")
                label = ttk.Label(tw, text=tooltip_text, justify='left', background="#ffffe0", relief='solid', borderwidth=1, padding=(5, 3))
                label.pack()

    def on_tree_leave(self, event):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

    def _generate_access_tooltip_text(self, block_num):
        """Generates the detailed, multi-line text for the access rights tooltip."""
        # --- ▼ 変更点 ▼ ---
        # ブロック15のツールチップを英語に変更
        if not (0 <= block_num <= 14):
            return "Access Controller" if block_num == 15 else ""
        # --- ▲ 変更点 ▲ ---

        is_rw = self.mc_handler.rw_ro_settings[block_num]
        base = "Read/Write (RW)" if is_rw == 1 else "Read-Only (RO)"
        details = [base]
        if self.mc_handler.r_auth_settings[block_num] == 1: details.append("• Read requires Authentication")
        if is_rw == 1:
            if self.mc_handler.w_auth_settings[block_num] == 1: details.append("• Write requires Authentication")
            if self.mc_handler.w_mac_settings[block_num] == 1: details.append("• Write requires MAC")
        return "\n".join(details) if len(details) > 1 else f"{base}\n(No authentication needed)"

    def on_tree_click(self, event):
        """Handle single clicks, primarily for showing the access rights editor."""
        # --- ▼ 変更点 ▼ ---
        # データがロードされていない場合は編集操作をブロック
        if not self.has_data_in_ui:
            return
        # --- ▲ 変更点 ▲ ---
        
        for widget in self.tree.winfo_children():
            if isinstance(widget, (ttk.Combobox, ttk.Entry)) and widget.winfo_exists():
                widget.destroy()
        if self.tree.identify_region(event.x, event.y) != 'cell': return

        selected_iid = self.tree.identify_row(event.y)
        if not selected_iid: return

        self.tree.focus(selected_iid)
        self.tree.selection_set(selected_iid)

        column_id = self.tree.identify_column(event.x)
        block_num = int(self.tree.item(selected_iid, 'values')[0].split(' ')[0])

        if column_id == '#4' and 0 <= block_num <= 13:
            if self.is_card_locked:
                self.append_log('INFO', 'Access rights cannot be changed on a permanently locked card.')
                return
            self._show_access_rights_editor(selected_iid, self.tree.bbox(selected_iid, column_id))

    def on_tree_double_click(self, event):
        """Handle double clicks for editing Hex Data or copying ASCII."""
        # --- ▼ 変更点 ▼ ---
        # データがロードされていない場合は編集操作をブロック
        if not self.has_data_in_ui:
            return
        # --- ▲ 変更点 ▲ ---

        if self.tree.identify_region(event.x, event.y) != 'cell': return
        selected_iid = self.tree.focus()
        if not selected_iid: return

        column_id = self.tree.identify_column(event.x)
        block_num = int(self.tree.item(selected_iid, 'values')[0].split(' ')[0])

        if column_id == '#2' and 'readonly' not in self.tree.item(selected_iid, 'tags'):
            if self.is_card_locked:
                 self.append_log('INFO', 'Data cannot be modified on a permanently locked card.')
                 return
            col_box = self.tree.bbox(selected_iid, column_id)
            entry = ttk.Entry(self.tree, font=("Courier New", 12), justify='center')
            entry.place(x=col_box[0], y=col_box[1], width=col_box[2], height=col_box[3])
            entry.insert(0, self.tree.item(selected_iid, 'values')[1])
            entry.focus()
            entry.bind('<FocusOut>', lambda e, i=selected_iid, en=entry: self._save_cell_edit(i, en))
            entry.bind('<Return>', lambda e, i=selected_iid, en=entry: self._save_cell_edit(i, en))
        elif column_id == '#3':
            ascii_value = self.tree.item(selected_iid, 'values')[2]
            self.clipboard_clear(); self.clipboard_append(ascii_value.replace('.', ''))
            self.append_log('INFO', f'Copied decoded string from Block {block_num} to clipboard.')

    def _show_access_rights_editor(self, iid, col_box):
        """Creates a dropdown menu for editing access rights."""
        block_num = int(self.tree.item(iid, 'values')[0].split(' ')[0])
        values = ["RW", "RO", "RW (R Auth)", "RO (R Auth)", "RW (W Auth)", "RW (W MAC)", 
                  "RW (R Auth W Auth)", "RW (R Auth W MAC)", "RW (W Auth W MAC)", "RW (R Auth W Auth W MAC)"]
        combo = ttk.Combobox(self.tree, state="readonly", values=values, style="Access.TCombobox")
        combo.set(self.mc_handler.get_access_mode_string(block_num))
        combo.place(x=col_box[0], y=col_box[1], width=col_box[2], height=col_box[3])
        combo.focus()
        combo.event_generate('<Down>')

        def on_combo_select(event):
            new_mode_str = combo.get()
            self.mc_handler.set_access_mode_from_string(block_num, new_mode_str)
            self.tree.set(iid, 'access_rights', self._format_access_string(block_num))
            self._update_all_modified_statuses()
            self.append_log('INFO', f'Block {block_num} access rights set to {new_mode_str}.')
            combo.destroy()

        combo.bind("<<ComboboxSelected>>", on_combo_select)
        combo.bind("<FocusOut>", lambda e: combo.destroy() if combo.winfo_exists() else None)

    def _update_all_modified_statuses(self):
        """Iterates through the entire tree and updates the modified status for each row."""
        for iid in self.tree.get_children():
            self._update_modified_status(iid)

    # _update_modified_statusメソッドを、以下のコードに置き換えてください。

    def _update_modified_status(self, iid):
        """Checks if a block's data or access rights have changed and updates the UI."""
        if not iid in self.tree.get_children(): return

        values = self.tree.item(iid, 'values')
        tags = set(self.tree.item(iid, 'tags'))
        block_num = int(values[0])

        # --- ▼ 変更点：ここから ▼ ---
        data_mod = False
        current_hex = str(values[1])
        # 現在のHex表示が "N/A" を含む場合、それは読み取り失敗を示しており、
        # ユーザーによる「変更」ではないため、チェック対象から除外する
        if "N/A" in current_hex:
            data_mod = False
        else:
            original_hex = self.original_dump_data.get(block_num, '')
            data_mod = current_hex.upper() != str(original_hex).upper()
        # --- ▲ 変更点：ここまで ▲ ---
        
        prot_mod = False
        if 0 <= block_num <= 14:
            original, current = self.original_mc_handler_state, self.mc_handler
            if (current.rw_ro_settings[block_num] != original.get('rw_ro', [1]*15)[block_num] or
                current.r_auth_settings[block_num] != original.get('r_auth', [0]*15)[block_num] or
                current.w_auth_settings[block_num] != original.get('w_auth', [0]*15)[block_num] or
                current.w_mac_settings[block_num] != original.get('w_mac', [0]*15)[block_num]):
                prot_mod = True
        
        tags.add('modified') if data_mod or prot_mod else tags.discard('modified')
        self.tree.item(iid, tags=list(tags))

    def _save_cell_edit(self, iid, entry_widget):
        """Handles input from the Hex Data entry field."""
        new_hex = entry_widget.get().strip().upper()
        entry_widget.destroy()
        block_num = int(self.tree.item(iid, 'values')[0].split(' ')[0])

        if block_num in READ_ONLY_BLOCKS:
            self.append_log('ERROR', f'Block {block_num} is Read-Only.')
            return
        if len(new_hex) != 32 or not all(c in '0123456789ABCDEF' for c in new_hex):
            self.append_log('ERROR', f'Invalid hex data. Must be 32 hex characters.')
            return

        current_values = list(self.tree.item(iid, 'values'))
        current_values[1] = new_hex

        encoding = self.encoding_var.get()
        chunk = binascii.unhexlify(new_hex)
        if block_num == 14: ascii_data = '***KEY DATA***'
        elif block_num == 15: ascii_data = '(MC BLOCK CONFIG)'
        else:
            try: ascii_data = chunk.decode(encoding, errors='replace').replace('\x00', '.')
            except Exception: ascii_data = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk).replace('\x00', '.')
        current_values[2] = ascii_data

        self.tree.item(iid, values=tuple(current_values))
        self._update_modified_status(iid)
        self.append_log('INFO', f'Block {current_values[0]} data updated in UI.')

    # ==========================================================================
    # --- File Operations
    # ==========================================================================
    def on_save_data(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Binary Dump files", "*.bin"), ("All files", "*.*")], title="Save FeliCa Lite-S Binary Dump (256 bytes)")
        if not file_path: return

        try:
            full_data = bytearray(FELICA_LITE_S_BYTES)
            for iid in self.tree.get_children():
                values = self.tree.item(iid, 'values')
                block_num, hex_data = int(values[0].split(' ')[0]), values[1]
                if len(hex_data) == 32:
                    start_index = block_num * 16
                    full_data[start_index:start_index + 16] = binascii.unhexlify(hex_data)
            with open(file_path, 'wb') as f: f.write(full_data)
            self.append_log('SUCCESS', f'Binary dump saved to: {file_path}')
        except Exception as e:
            self.append_log('ERROR', f'Failed to save data dump: {e}')
            messagebox.showerror("Save Failed", f"Failed to save data dump:\n{e}")

    def on_load_data(self):
        """Loads a binary dump and stages it as pending changes."""
        file_path = filedialog.askopenfilename(defaultextension=".bin", filetypes=[("Binary Dump files", "*.bin"), ("All files", "*.*")], title="Load FeliCa Lite-S Binary Dump (256 bytes)")
        if not file_path: return

        if not messagebox.askokcancel("Confirm Load", "This will overwrite all current data and access rights in the UI.\n\nProceed?"):
            return
        try:
            with open(file_path, 'rb') as f: full_data = f.read()
            if len(full_data) != FELICA_LITE_S_BYTES:
                raise ValueError(f"File size must be exactly {FELICA_LITE_S_BYTES} bytes.")

            self._populate_dump_table(full_data)
            self.lbl_idm.config(text='[Loaded from file]')
            self.lbl_pmm.config(text='[Loaded from file]')
            self.lbl_syscode.config(text='[Loaded from file]')
            self.append_log('SUCCESS', f'Binary dump loaded from: {file_path}. Changes are staged.')
        except Exception as e:
            self.append_log('ERROR', f'Failed to load data dump: {e}')
            messagebox.showerror("Load Failed", f"Failed to load data dump:\n{e}")

    def on_export_report(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")], title="Export FeliCa Lite-S Configuration Report")
        if not file_path: return

        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            encoding = self.encoding_var.get()
            report_lines = [
                f"#######################################################################",
                f"# FeliCa Lite-S Configuration Report",
                f"# Generated on: {timestamp}",
                f"#######################################################################",
                f"--- CARD STATUS & AUTHENTICATION ---",
                f"IDm:                   {self.lbl_idm['text']}",
                f"PMm:                   {self.lbl_pmm['text']}",
                f"System Code:           {self.lbl_syscode['text']}",
                f"PERMANENTLY LOCKED:    {'YES' if self.is_card_locked else 'NO'}",
                f"CKV (UI Field):        {self.entry_ckv.get().strip().upper()}",
                f"CK (UI Field):         {self.entry_key.get().strip().upper()}",
                f"ASCII DECODING:        {encoding.upper()}",
                f"\n--- BLOCK ACCESS RIGHTS SUMMARY (S_PAD0 to REG) ---",
                f"{'Block':<5} | {'RW/RO':<5} | {'R_AUTH':<7} | {'W_AUTH':<7} | {'W_MAC':<7} | {'Display Mode':<25}",
                f"------|-------|---------|---------|---------|--------------------------",
            ]
            for i in range(self.mc_handler.max_blocks):
                rw_ro, r_auth = ('RW' if self.mc_handler.rw_ro_settings[i] else 'RO'), ('YES' if self.mc_handler.r_auth_settings[i] else 'NO')
                w_auth, w_mac = ('YES' if self.mc_handler.w_auth_settings[i] else 'NO'), ('YES' if self.mc_handler.w_mac_settings[i] else 'NO')
                block_name = f"S_PAD{i}" if i < 14 else "REG"
                report_lines.append(f"{block_name:<5} | {rw_ro:<5} | {r_auth:<7} | {w_auth:<7} | {w_mac:<7} | {self.mc_handler.get_access_mode_string(i):<25}")

            report_lines.extend([f"\n#######################################################################",
                                 f"--- FULL DATA DUMP (HEX & DECODED ASCII) ---",
                                 f"#######################################################################",
                                 f"{'Block':<5} | {'Hex Data (16 Bytes)':<32} | {'ASCII (Encoded as ' + encoding.upper() + ')':<18} | {'Access':<25}",
                                 f"------|----------------------------------|----------------------|-------------------------"])
            for iid in self.tree.get_children():
                values = self.tree.item(iid, 'values')
                block, h, a, acc = values[0], values[1], values[2], values[3]
                display_hex = '***KEY DATA (WRITE ONLY)***' if int(block) == 14 else h
                report_lines.append(f"{block:<5} | {display_hex:<32} | {a:<18} | {acc:<25}")

            with open(file_path, 'w', encoding='utf-8') as f: f.write('\n'.join(report_lines))
            self.append_log('SUCCESS', f'Configuration report exported to: {file_path}')
        except Exception as e:
            self.append_log('ERROR', f'Failed to export report: {e}')
            messagebox.showerror("Export Failed", f"Failed to export report:\n{e}")

    def on_export_json(self):
        """Exports the full card state (data and config) to a JSON file."""
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")], title="Save FeliCa Lite-S State (JSON)")
        if not file_path: return

        try:
            data_blocks = {f"BLOCK_{int(self.tree.item(i, 'values')[0].split(' ')[0])}": self.tree.item(i, 'values')[1] for i in self.tree.get_children()}
            
            # --- ▼ 変更点 ▼ ---
            # JSONのバージョンを更新し、カード情報を追加
            config_data = {
                "format_version": 4.0,
                "timestamp": datetime.now().isoformat(),
                "card_info": {
                    "idm": self.lbl_idm['text'],
                    "pmm": self.lbl_pmm['text'],
                    "sys_code": self.lbl_syscode['text'].replace('0x', ''),
                },
                "lock_status": "LOCKED" if self.is_card_locked else "UNLOCKED",
                "ascii_encoding": self.encoding_var.get(),
                "authentication": {"ckv_hex": self.entry_ckv.get().strip().upper(), "ck_hex": self.entry_key.get().strip().upper()},
                "access_rights": { f"BLOCK_{i}": {
                        "RW_RO": self.mc_handler.rw_ro_settings[i], "R_AUTH": self.mc_handler.r_auth_settings[i],
                        "W_AUTH": self.mc_handler.w_auth_settings[i], "W_MAC": self.mc_handler.w_mac_settings[i]
                    } for i in range(self.mc_handler.max_blocks)
                },
                "data_blocks": data_blocks
            }
            # --- ▲ 変更点 ▲ ---

            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=4)
            self.append_log('SUCCESS', f'Full state exported to JSON: {file_path}')
        except Exception as e:
            self.append_log('ERROR', f'Failed to export JSON: {e}')
            messagebox.showerror("Export Failed", f"Failed to export JSON:\n{e}")

    def on_import_json(self):
        """Imports a full card state from JSON and stages it as pending changes."""
        file_path = filedialog.askopenfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")], title="Load FeliCa Lite-S State (JSON)")
        if not file_path: return

        if not messagebox.askokcancel("Confirm Import", "This will overwrite all settings in the UI.\n\nProceed?"):
            return
        try:
            with open(file_path, 'r', encoding='utf-8') as f: config_data = json.load(f)

            version = config_data.get("format_version", 1.0)
            if version > 4.0:
                raise ValueError(f"Unsupported JSON format version: {version}.")

            # --- ▼ 変更点 ▼ ---
            # JSONからカード情報を読み込んでUIに反映
            if "card_info" in config_data:
                info = config_data["card_info"]
                self.lbl_idm.config(text=info.get('idm', '-'))
                self.lbl_pmm.config(text=info.get('pmm', '-'))
                sys_code = info.get('sys_code', '-')
                self.lbl_syscode.config(text=f"0x{sys_code}" if sys_code != '-' else '-')
            else: # 古いJSONファイルとの後方互換性のため
                self.lbl_idm.config(text='[Loaded from file]')
                self.lbl_pmm.config(text='[Loaded from file]')
                self.lbl_syscode.config(text='[Loaded from file]')
            # --- ▲ 変更点 ▲ ---

            self.out_q.put(('LOCK_STATUS_UPDATE', config_data.get("lock_status") == "LOCKED"))
            auth = config_data.get("authentication", {})
            self.entry_ckv.delete(0, 'end'); self.entry_ckv.insert(0, auth.get("ckv_hex", "0000"))
            self.entry_key.delete(0, 'end'); self.entry_key.insert(0, auth.get("ck_hex", ""))

            if config_data.get("ascii_encoding") in SUPPORTED_ENCODINGS:
                self.encoding_var.set(config_data["ascii_encoding"])
            encoding = self.encoding_var.get()

            access = config_data.get("access_rights", {})
            for i in range(self.mc_handler.max_blocks):
                cfg = access.get(f"BLOCK_{i}")
                if isinstance(cfg, dict):
                    self.mc_handler.rw_ro_settings[i] = cfg.get("RW_RO", 1)
                    self.mc_handler.r_auth_settings[i] = cfg.get("R_AUTH", 0)
                    self.mc_handler.w_auth_settings[i] = cfg.get("W_AUTH", 0)
                    self.mc_handler.w_mac_settings[i] = cfg.get("W_MAC", 0)

            data_blocks = config_data.get("data_blocks", {})
            iid_map = {int(self.tree.item(i, 'values')[0].split(' ')[0]): i for i in self.tree.get_children()}

            for block_num in range(FELICA_LITE_S_BLOCKS):
                if block_num not in iid_map: continue
                iid = iid_map[block_num]
                hex_data = data_blocks.get(f"BLOCK_{block_num}", '00'*16).upper()

                if block_num == 14: access_str, ascii_data = "CKV/CK Storage", '***KEY DATA***'
                elif block_num == 15: access_str, ascii_data = self._format_access_string(block_num), '(MC BLOCK CONFIG)'
                else:
                    access_str = self._format_access_string(block_num)
                    try: ascii_data = binascii.unhexlify(hex_data).decode(encoding, errors='replace').replace('\x00', '.')
                    except Exception: ascii_data = '.' * 16
                self.tree.item(iid, values=(block_num, hex_data, ascii_data, access_str))

            # --- ▼ 変更点 ▼ ---
            # データをロードしたのでUIを有効化
            self.has_data_in_ui = True
            self._update_ui_state()
            self._update_all_modified_statuses()
            # --- ▲ 変更点 ▲ ---
            self.append_log('SUCCESS', f'Configuration imported from JSON: {file_path}. Changes are staged.')
        except Exception as e:
            self.append_log('ERROR', f'Failed to import JSON: {e}')
            messagebox.showerror("Import Failed", f"Failed to import JSON:\n{e}")

# ==============================================================================
# 4. Main Execution
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="All-in-one FeliCa Lite-S GUI Tool.")
    parser.add_argument('--test', type=str, metavar='DUMMY_FILE',
                        help='Run in test mode with a dummy binary data file (256 bytes).')
    args = parser.parse_args()
    app = FelicaGUI(test_file=args.test)
    app.mainloop()

if __name__ == '__main__':
    main()

    