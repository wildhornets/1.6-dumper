"""
https://github.com/wildhornets/1.6-dumper
"""
import ctypes
import ctypes.wintypes as wt
import struct
import time
import sys
import os
import json
import threading
import msvcrt
import math
import re

# Force UTF-8 output on Windows console
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
user32   = ctypes.WinDLL('user32',   use_last_error=True)

PROCESS_ALL_ACCESS  = 2035711
MEM_COMMIT          = 4096
PAGE_READABLE       = (2, 4, 8, 32, 64, 128)
TH32CS_SNAPPROCESS  = 2
TH32CS_SNAPMODULE   = 24

R = '\033[91m'
G = '\033[92m'
Y = '\033[93m'
C = '\033[96m'
M = '\033[95m'
W = '\033[97m'
D = '\033[90m'
B = '\033[1m'
X = '\033[0m'

if getattr(sys, 'frozen', False):
    DIR = os.path.dirname(sys.executable)
else:
    DIR = os.path.dirname(os.path.abspath(__file__))

OFFSETS_FILE = os.path.join(DIR, 'cs16_offsets.json')
SIGS_FILE    = os.path.join(DIR, 'cs16_signatures.json')

# ── Win32 structures ─────────────────────────────────────────────────────────

class PE32W(ctypes.Structure):
    _fields_ = [
        ('dwSize',            wt.DWORD),
        ('cntUsage',          wt.DWORD),
        ('th32ProcessID',     wt.DWORD),
        ('th32DefaultHeapID', ctypes.c_void_p),
        ('th32ModuleID',      wt.DWORD),
        ('cntThreads',        wt.DWORD),
        ('th32ParentProcessID', wt.DWORD),
        ('pcPriClassBase',    ctypes.c_long),
        ('dwFlags',           wt.DWORD),
        ('szExeFile',         ctypes.c_wchar * 260),
    ]

class ME32W(ctypes.Structure):
    _fields_ = [
        ('dwSize',       wt.DWORD),
        ('th32ModuleID', wt.DWORD),
        ('th32ProcessID',wt.DWORD),
        ('GlbcntUsage',  wt.DWORD),
        ('ProccntUsage', wt.DWORD),
        ('modBaseAddr',  ctypes.c_void_p),
        ('modBaseSize',  wt.DWORD),
        ('hModule',      wt.HMODULE),
        ('szModule',     ctypes.c_wchar * 256),
        ('szExePath',    ctypes.c_wchar * 260),
    ]

class MBI(ctypes.Structure):
    _fields_ = [
        ('BaseAddress',      ctypes.c_void_p),
        ('AllocationBase',   ctypes.c_void_p),
        ('AllocationProtect',wt.DWORD),
        ('RegionSize',       ctypes.c_size_t),
        ('State',            wt.DWORD),
        ('Protect',          wt.DWORD),
        ('Type',             wt.DWORD),
    ]

# ── Process helpers ───────────────────────────────────────────────────────────

def find_pid(name):
    """Return PID of a process by name, or 0 if not found."""
    s = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if s in (-1, 0):
        return 0
    e   = PE32W()
    e.dwSize = ctypes.sizeof(PE32W)
    pid = 0
    if kernel32.Process32FirstW(s, ctypes.byref(e)):
        while True:
            if e.szExeFile.lower() == name.lower():
                pid = e.th32ProcessID
                break
            if not kernel32.Process32NextW(s, ctypes.byref(e)):
                break
    kernel32.CloseHandle(s)
    return pid

def get_modules(pid):
    """Return list of (name, base, size) for all modules in pid."""
    mods = []
    s = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    if s in (-1, 0):
        return mods
    e = ME32W()
    e.dwSize = ctypes.sizeof(ME32W)
    if kernel32.Module32FirstW(s, ctypes.byref(e)):
        while True:
            mods.append((e.szModule, e.modBaseAddr or 0, e.modBaseSize))
            if not kernel32.Module32NextW(s, ctypes.byref(e)):
                break
    kernel32.CloseHandle(s)
    return mods

# ── Memory read/write ────────────────────────────────────────────────────────

def rpm_int(h, a):
    b = ctypes.c_int(0)
    kernel32.ReadProcessMemory(h, ctypes.c_void_p(a), ctypes.byref(b), 4, None)
    return b.value

def rpm_float(h, a):
    b = ctypes.c_float(0)
    kernel32.ReadProcessMemory(h, ctypes.c_void_p(a), ctypes.byref(b), 4, None)
    return b.value

def rpm_uint(h, a):
    b = ctypes.c_uint(0)
    kernel32.ReadProcessMemory(h, ctypes.c_void_p(a), ctypes.byref(b), 4, None)
    return b.value

def wpm_int(h, a, v):
    b = ctypes.c_int(v)
    kernel32.WriteProcessMemory(h, ctypes.c_void_p(a), ctypes.byref(b), 4, None)

def key_pressed(vk):
    return user32.GetAsyncKeyState(vk) & 32768

# ── Memory scanner ────────────────────────────────────────────────────────────

class MemScanner:
    def __init__(self, handle):
        self.h       = handle
        self.results = {}

    def get_regions(self):
        regions = []
        addr    = 0
        mbi     = MBI()
        while kernel32.VirtualQueryEx(self.h, ctypes.c_void_p(addr),
                                      ctypes.byref(mbi), ctypes.sizeof(mbi)):
            base  = mbi.BaseAddress or 0
            rsize = mbi.RegionSize  or 0
            if (mbi.State == MEM_COMMIT
                    and mbi.Protect in PAGE_READABLE
                    and 0 < rsize < 268435456):
                regions.append((base, rsize))
            addr = base + rsize
            if addr <= 0 or addr > 2147483647:
                break
        return regions

    def read_region(self, addr, size):
        buf = ctypes.create_string_buffer(size)
        br  = ctypes.c_size_t(0)
        if (kernel32.ReadProcessMemory(self.h, ctypes.c_void_p(addr),
                                       buf, size, ctypes.byref(br))
                and br.value > 0):
            return buf.raw[:br.value]
        return None

    def first_scan(self, value, fmt='<i'):
        self.results.clear()
        sz      = struct.calcsize(fmt)
        for base, rsize in self.get_regions():
            data = self.read_region(base, rsize)
            if not data:
                continue
            for off in range(0, len(data) - sz + 1, 4):
                try:
                    v = struct.unpack_from(fmt, data, off)[0]
                    if v == value:
                        self.results[base + off] = v
                except Exception:
                    pass
        return len(self.results)

    def next_scan(self, value, fmt='<i'):
        sz  = struct.calcsize(fmt)
        new = {}
        for addr in self.results:
            data = self.read_region(addr, sz)
            if data:
                try:
                    cur = struct.unpack(fmt, data)[0]
                    if cur == value:
                        new[addr] = cur
                except Exception:
                    pass
        self.results = new
        return len(self.results)

# ── CE-style scanning helpers ─────────────────────────────────────────────────

def calibrate_ce(scanner, name, tip, ranges):
    """Helper for CE-style Changed/Unchanged scanning (Automatic)."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f'\n  {C}[CE MODE] {B}{name}{X}\n  {D}Hint: {tip}{X}')
    candidate_list = []
    for base, size in ranges:
        for i in range(0, size - 4, 4):
            candidate_list.append(base + i)
    while len(candidate_list) > 1:
        print(f'  {C}Candidates: {G}{len(candidate_list)}{X} | [1] Changed [2] Unchanged [ok] Finish')
        cmd = input(f'  {B}> {X}').strip().lower()
        if cmd == 'ok':
            break
        if cmd not in ['1', '2']:
            continue
        is_changed = (cmd == '1')
        new_res    = []
        for addr in candidate_list:
            v1 = rpm_float(scanner.h, addr)
            time.sleep(1e-5)
            v2 = rpm_float(scanner.h, addr)
            if is_changed:
                if abs(v2 - v1) > 0.0001:
                    new_res.append(addr)
            else:
                if abs(v2 - v1) < 0.0001:
                    new_res.append(addr)
        candidate_list = new_res
        if not candidate_list:
            print(f'  {R}[!] No results left!{X}')
            return None
    return candidate_list[0] if candidate_list else None

# ── Main calibration scanner ──────────────────────────────────────────────────

def calibrate_value(scanner, name, question1, question2, fmt='<i',
                    module_ranges=None, first_val=None, max_attempts=25):
    """Guide user to find a specific memory address."""
    print(f"\n{C}{'──────────────────────────────────────────────────'}{X}")
    print(f'{B}{Y}  CALIBRATION: {name}{X}')
    print(f"{C}{'──────────────────────────────────────────────────'}{X}")

    if first_val is not None:
        val = first_val
    else:
        if question1:
            val_str = input(
                f'\n  {W}{question1}{X}\n  {D}(\'skip\' to skip){X}\n  {B}> {X}'
            ).strip()
            if val_str.lower() in ['skip', 's']:
                print(f'  {Y}[*] {name} skipped.{X}')
                return None
            try:
                val = float(val_str) if 'f' in fmt else int(val_str)
            except Exception:
                print(f'  {R}Invalid!{X}')
                return None
            if val == 0:
                print(f'  {Y}[!] Scanning 0 yields too many results. Skip? (y/n){X}')
                if input(f'  {B}> {X}').strip().lower() in ['y', 'yes', '']:
                    return None
        else:
            return None

    print(f'  {C}[*] Scanning {val} (game modules only)...{X}')

    if module_ranges:
        scanner.results.clear()
        sz = struct.calcsize(fmt)
        for base, size in module_ranges:
            data = scanner.read_region(base, size)
            if not data:
                continue
            for off in range(0, len(data) - sz + 1, 4):
                try:
                    v = struct.unpack_from(fmt, data, off)[0]
                    if fmt == '<f':
                        if abs(v - val) < 0.5:
                            scanner.results[base + off] = v
                    else:
                        if v == val:
                            scanner.results[base + off] = v
                except Exception:
                    pass
        count = len(scanner.results)
    else:
        count = scanner.first_scan(val, fmt)

    print(f'  {D}  {count} addresses found{X}')
    if count == 0:
        print(f'  {R}[!] Not found!{X}')
        return None

    attempts = 0
    while count > 1 and attempts < max_attempts:
        attempts += 1
        print(f'\n  {D}[Scan {attempts}/{max_attempts} | {count} addresses left]{X}')
        val_str = input(
            f'  {W}{question2}{X}\n  {D}(\'skip\' to skip, \'ok\' to go live){X}\n  {B}> {X}'
        ).strip()

        if val_str.lower() in ['skip', 's', 'atla']:
            return None
        if val_str.lower() in ['ok', 'tamam', 'devam']:
            break

        is_range = (val_str == '1-32')

        try:
            val = float(val_str) if 'f' in fmt else int(val_str)
        except Exception:
            continue

        new = {}
        for addr in scanner.results:
            if 'f' in fmt:
                cur = rpm_float(scanner.h, addr)
                if not is_range and abs(cur - val) < 0.5:
                    new[addr] = cur
            else:
                cur = rpm_int(scanner.h, addr)
                if is_range:
                    if 1 <= cur <= 32:
                        new[addr] = cur
                else:
                    if cur == val:
                        new[addr] = cur
        scanner.results = new
        count = len(new)
        print(f'  {D}  {count} addresses left{X}')
        if count == 0:
            print(f'  {R}[!] All addresses eliminated.{X}')
            return None

    if not scanner.results:
        return None

    # ── Live view: user picks from list ──────────────────────────────────────
    def get_mod_name(a):
        if module_ranges:
            for idx, (base, size) in enumerate(module_ranges):
                if base <= a < base + size:
                    return 'client.dll' if idx == 0 else 'hw.dll'
        return '?'

    addrs    = list(scanner.results.keys())
    h        = scanner.h
    page     = 0
    pp       = 20
    chosen   = None
    input_buf = ''

    while chosen is None:
        os.system('cls' if os.name == 'nt' else 'clear')
        total_pages = (len(addrs) + pp - 1) // pp
        s = page * pp
        e = min(s + pp, len(addrs))
        print(f'  {B}{Y}LIVE VIEW - {name}{X}  {D}Page {page+1}/{total_pages} | {len(addrs)} addresses{X}')
        print(f'  {D}Auto-refreshing. Change value in-game, which one matches?{X}')
        print(f"  {C}{'#':<5} {'ADDRESS':<14} {'VALUE':<12} {'MODULE'}{X}")
        print(f"  {D}{'──────────────────────────────────────────────────'}{X}")
        for i in range(s, e):
            addr    = addrs[i]
            mod     = get_mod_name(addr)
            if 'f' in fmt:
                cur     = rpm_float(h, addr)
                cur_str = f'{cur:.1f}'
            else:
                cur     = rpm_int(h, addr)
                cur_str = str(cur)
            print(f'  {W}{i:<5}{X} {M}0x{addr:08X}{X} {Y}{cur_str:<12}{X} {G}{mod}{X}')

        print(f"\n  {D}{'──────────────────────────────────────────────────'}{X}")
        print(f'  {C}[n]{X} Next  {C}[p]{X} Prev  {C}[number]{X} Select  {C}[q]{X} Skip')
        print(f'  {R}[e+no]{X} Elim  {Y}[a]{X} Use All  {M}[f]{X} Filter Still')
        print(f'  {B}[v+val]{X} Filter Value (e.g. v100)')
        if input_buf:
            print(f'  {B}Input: {input_buf}{X}')

        deadline = time.time() + 0.5
        while time.time() < deadline:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch == '\r':
                    cmd       = input_buf.strip().lower()
                    input_buf = ''
                    if cmd == 'n' and e < len(addrs):
                        page += 1
                    elif cmd == 'p' and page > 0:
                        page -= 1
                    elif cmd == 'q':
                        return None
                    elif cmd == 'a':
                        print(f'\n  {G}{B}[+] ALL {len(addrs)} ADDRESSES SAVED!{X}')
                        print(f'  {D}Reads first, writes to ALL.{X}')
                        time.sleep(1)
                        return addrs
                    elif cmd.startswith('e') and len(cmd) > 1:
                        try:
                            eidx = int(cmd[1:])
                            if 0 <= eidx < len(addrs):
                                removed = addrs.pop(eidx)
                                scanner.results.pop(removed, None)
                                if page * pp >= len(addrs) and page > 0:
                                    page -= 1
                        except Exception:
                            pass
                    elif cmd == 'f':
                        print(f'\n  {M}[*] STAY STILL! Wait 2s...{X}')
                        snap1 = {}
                        for addr in addrs:
                            snap1[addr] = rpm_float(h, addr) if 'f' in fmt else rpm_int(h, addr)
                        time.sleep(1.5)
                        removed_count = 0
                        keep = []
                        for addr in addrs:
                            if 'f' in fmt:
                                v2   = rpm_float(h, addr)
                                diff = abs(v2 - snap1[addr])
                                if diff < 0.1:
                                    keep.append(addr)
                                else:
                                    removed_count += 1
                            else:
                                v2 = rpm_int(h, addr)
                                if v2 == snap1[addr]:
                                    keep.append(addr)
                                else:
                                    removed_count += 1
                        addrs = keep
                        for addr in list(scanner.results.keys()):
                            if addr not in addrs:
                                scanner.results.pop(addr, None)
                        page = 0
                        print(f'  {G}[+] {removed_count} addresses eliminated, {len(addrs)} left{X}')
                        time.sleep(0.5)
                    elif cmd.startswith('v') and len(cmd) > 1:
                        try:
                            target = float(cmd[1:]) if 'f' in fmt else int(cmd[1:])
                            keep   = []
                            for addr in addrs:
                                if 'f' in fmt:
                                    cur = rpm_float(h, addr)
                                    if abs(cur - target) < 0.5:
                                        keep.append(addr)
                                else:
                                    cur = rpm_int(h, addr)
                                    if cur == target:
                                        keep.append(addr)
                            removed_count = len(addrs) - len(keep)
                            addrs = keep
                            for addr in list(scanner.results.keys()):
                                if addr not in addrs:
                                    scanner.results.pop(addr, None)
                            page = 0
                            print(f'  {G}[+] {removed_count} eliminated, {len(addrs)} left (value={target}){X}')
                            time.sleep(0.5)
                        except Exception:
                            pass
                    else:
                        try:
                            idx = int(cmd)
                            if 0 <= idx < len(addrs):
                                chosen = addrs[idx]
                        except Exception:
                            pass
                    break
                elif ch == '\b':
                    input_buf = input_buf[:-1]
                else:
                    input_buf += ch
            time.sleep(0.02)

    if chosen is None:
        return None
    val_now = scanner.results.get(chosen, 0)
    print(f'  {G}[+] {name} FOUND: 0x{chosen:08X} = {val_now}{X}')
    return chosen

# ── Force-command finder ──────────────────────────────────────────────────────

def find_forcecmd(handle, modules, cmd_name):
    """Find ForceAttack/ForceJump by searching for +attack/+jump strings."""
    for mod_name, base, size in modules:
        if mod_name.lower() != 'client.dll':
            continue
        buf = ctypes.create_string_buffer(min(size, 8388608))
        br  = ctypes.c_size_t(0)
        if not kernel32.ReadProcessMemory(handle, ctypes.c_void_p(base),
                                          buf, len(buf), ctypes.byref(br)):
            continue
        data   = buf.raw[:br.value]
        search = cmd_name.encode() + b'\x00'
        idx    = data.find(search)
        if idx < 0:
            continue
        str_addr = base + idx
        packed   = struct.pack('<I', str_addr)
        ref      = data.find(packed)
        if ref < 0:
            continue
        for delta in range(-128, 128):
            p = ref + delta
            if p < 0 or p >= len(data) - 6:
                continue
            if data[p] == 0xA3:  # MOV [addr], eax
                target = struct.unpack_from('<I', data, p + 1)[0]
                if 65536 < target < 2147483647:
                    return target
            if data[p] == 0x89 and data[p + 1] == 0x0D:  # MOV [addr], ecx
                target = struct.unpack_from('<I', data, p + 2)[0]
                if 65536 < target < 2147483647:
                    return target
    return 0

# ── All-memory region enumerator ──────────────────────────────────────────────

def get_all_memory_regions(handle):
    """Query all readable and committed memory regions in the process."""
    regions = []
    addr    = 0
    mbi     = MBI()
    while kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr),
                                  ctypes.byref(mbi), ctypes.sizeof(mbi)):
        if mbi.State == 4096 and mbi.Protect & 0xFC:
            regions.append((mbi.BaseAddress, mbi.RegionSize))
        addr = mbi.BaseAddress + mbi.RegionSize
    return regions

# ── Pattern scanner ───────────────────────────────────────────────────────────

def find_pattern_in_memory(handle, regions, pattern):
    """Scan for a hex pattern across multiple memory regions using fast regex."""
    re_pat = b''
    for p in pattern.split():
        if p == '??':
            re_pat += b'.'
        else:
            re_pat += b'\\x' + p.encode()
    compiled = re.compile(re_pat, re.DOTALL)
    results  = []
    for base, size in regions:
        buf = ctypes.create_string_buffer(size)
        br  = ctypes.c_size_t(0)
        if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(base),
                                      buf, size, ctypes.byref(br)):
            data = buf.raw[:br.value]
            for match in compiled.finditer(data):
                results.append(base + match.start())
    return results

def find_pattern_in_module(handle, base, size, pattern):
    return find_pattern_in_memory(handle, [(base, size)], pattern)

# ── Signature creator ─────────────────────────────────────────────────────────

def create_signature(handle, modules, target_addr):
    """Try to create a unique signature for a given address by finding code refs."""
    for mod_name, base, size in modules:
        if mod_name.lower() not in ['client.dll', 'hw.dll', 'engine.dll']:
            continue
        packed = struct.pack('<I', target_addr)
        buf    = ctypes.create_string_buffer(size)
        br     = ctypes.c_size_t(0)
        if not kernel32.ReadProcessMemory(handle, ctypes.c_void_p(base),
                                          buf, size, ctypes.byref(br)):
            continue
        data    = buf.raw[:br.value]
        ref_idx = data.find(packed)
        if ref_idx == -1:
            continue
        for radius in [10, 15, 20, 32, 48, 64]:
            start = max(0, ref_idx - radius)
            end   = min(len(data), ref_idx + 4 + radius)
            chunk = data[start:end]
            pattern_parts = []
            for i in range(len(chunk)):
                pos = start + i
                if ref_idx <= pos < ref_idx + 4:
                    pattern_parts.append('??')
                else:
                    pattern_parts.append(f'{chunk[i]:02X}')
            pattern  = ' '.join(pattern_parts)
            matches  = find_pattern_in_module(handle, base, size, pattern)
            if len(matches) == 1:
                rel_off = ref_idx - start
                return {'mod': mod_name, 'pat': pattern, 'off': rel_off}
    return None

# ── Full calibration ──────────────────────────────────────────────────────────

def run_calibration(handle, modules):
    """Full calibration: find all needed addresses."""
    print(f'\n{C}+=========================================================+')
    print(f'|  {B}CALIBRATION MODE{X}{C}                                       |')
    print(f'|  {D}Must be in-game. Answer questions, tool does the rest.{X}{C}|')
    print(f'+=========================================================+{X}\n')

    scanner     = MemScanner(handle)
    offsets     = {}
    client_base = client_size = hw_base = hw_size = 0

    for name, base, size in modules:
        if name.lower() == 'client.dll':
            client_base, client_size = base, size
        if name.lower() in ['hw.dll', 'engine.dll', 'sw.dll']:
            hw_base, hw_size = base, size

    offsets['client_base'] = client_base
    offsets['hw_base']     = hw_base

    game_ranges = []
    if client_base:
        game_ranges.append((client_base, client_size))
    if hw_base:
        game_ranges.append((hw_base, hw_size))

    print(f'  {D}Scanning modules: client.dll + hw.dll '
          f'({sum(s for _, s in game_ranges) // 1024}KB){X}')

    # ── Health ───────────────────────────────────────────────────────────────
    print(f"\n{C}{'──────────────────────────────────────────────────'}{X}")
    print(f'{B}{Y}  CALIBRATION: HEALTH{X}')
    print(f"{C}{'──────────────────────────────────────────────────'}{X}")
    print(f'  {D}Scanning as both float and int.{X}')
    val_str = input(f'\n  {W}What is your current health? (e.g. 100):{X}\n'
                    f'  {D}(\'skip\' to skip){X}\n  {B}> {X}').strip()
    if val_str.lower() not in ['skip', 's', 'atla']:
        try:
            val    = int(val_str)
            addr_f = calibrate_value(scanner, 'HEALTH [FLOAT]', None,
                                     'Take damage! Current health?',
                                     fmt='<f', module_ranges=game_ranges,
                                     first_val=float(val))
            int_val = val
            if addr_f:
                first_addr = addr_f[0] if isinstance(addr_f, list) else addr_f
                cur_float  = rpm_float(handle, first_addr)
                int_val    = int(cur_float)
                print(f'  {D}Using current value for int scan: {int_val}{X}')
            addr_i = calibrate_value(scanner, 'HEALTH [INT]', None,
                                     'Take damage! Current health?',
                                     fmt='<i', module_ranges=game_ranges,
                                     first_val=int_val)
            if addr_f:
                offsets['health_direct']   = addr_f
                offsets['health_is_float'] = True
            elif addr_i:
                offsets['health_direct']   = addr_i
                offsets['health_is_float'] = False
        except Exception:
            pass

    addr = calibrate_value(scanner, 'ARMOR',
                           'Current Armor? (0 to skip):',
                           'Change Armor! What is it now?',
                           fmt='<i', module_ranges=game_ranges)
    if addr:
        offsets['armor_direct'] = addr

    # ── Force commands ────────────────────────────────────────────────────────
    print(f"\n{C}{'──────────────────────────────────────────────────'}{X}")
    print(f'{B}{Y}  CALIBRATION: FORCE COMMANDS (+JUMP, +ATTACK){X}')
    print(f"{C}{'──────────────────────────────────────────────────'}{X}")
    print(f'  {D}Auto-scanning...{X}')
    fj = find_forcecmd(handle, modules, '+jump')
    if fj:
        offsets['force_jump'] = fj
        print(f'    {G}✓{X} {D}ForceJump: 0x{fj:08X} (+jump->5, -jump->4){X}')
    fa = find_forcecmd(handle, modules, '+attack')
    if fa:
        offsets['force_attack'] = fa
        print(f'    {G}✓{X} {D}ForceAttack: 0x{fa:08X} (+attack->5, -attack->4){X}')

    addr = calibrate_value(scanner, 'GROUND FLAG (for BHop)',
                           'On ground? (1 if yes, 0 if air):',
                           'Jump! In air=0, ground=1:',
                           fmt='<i', module_ranges=game_ranges)
    if addr:
        offsets['ground_flag'] = addr

    # ── Triggerbot ────────────────────────────────────────────────────────────
    print(f"\n{C}{'──────────────────────────────────────────────────'}{X}")
    print(f'{B}{Y}  CALIBRATION: CROSSHAIR ID (TRIGGERBOT){X}')
    print(f"{C}{'──────────────────────────────────────────────────'}{X}")
    addr = calibrate_value(scanner, 'CROSSHAIR (for Trigger)',
                           'Look at empty space and type 0:',
                           'Aim at player! Current value? (1-32):',
                           fmt='<i', module_ranges=game_ranges)
    if addr:
        offsets['crosshair_id'] = addr

    # ── No-flash / team / alive / weapon / ammo ───────────────────────────────
    print(f"\n{C}{'──────────────────────────────────────────────────'}{X}")
    print(f'{B}{Y}  CALIBRATION: NO-FLASH{X}')
    print(f"{C}{'──────────────────────────────────────────────────'}{X}")
    addr = calibrate_value(scanner, 'NO-FLASH', 'Flashed? (0 if no):',
                           'Throw Flash! Full white=255:',
                           fmt='<f', module_ranges=game_ranges)
    if addr:
        offsets['flash_alpha'] = addr

    addr = calibrate_value(scanner, 'TEAM', 'T=1, CT=2:', 'Change team, new value:',
                           fmt='<i', module_ranges=game_ranges)
    if addr:
        offsets['team'] = addr

    addr = calibrate_value(scanner, 'IS ALIVE', 'Alive=1:', 'Type kill, in console=0:',
                           fmt='<i', module_ranges=game_ranges)
    if addr:
        offsets['is_alive'] = addr

    addr = calibrate_value(scanner, 'WEAPON ID', 'Pistol ID:', 'Rifle ID:',
                           fmt='<i', module_ranges=game_ranges)
    if addr:
        offsets['weapon_id'] = addr

    addr = calibrate_value(scanner, 'CLIP AMMO', 'Current Ammo:', 'Shoot, remaining ammo:',
                           fmt='<i', module_ranges=game_ranges)
    if addr:
        offsets['clip_ammo'] = addr

    # ── Recoil / punch angle ──────────────────────────────────────────────────
    print(f'  {C}[1]{X} Normal | {C}[2]{X} CE Mode (Auto)')
    p_mode = input(f'  {B}Recoil Mode > {X}').strip()
    if p_mode == '2':
        addr = calibrate_ce(scanner, 'PUNCHANGLE',
                            '1 while shooting, 2 while idle.', game_ranges)
    else:
        addr = calibrate_value(scanner, 'PUNCHANGLE (Recoil)',
                               '0 while idle:', 'Changed while shooting:',
                               fmt='<f', module_ranges=game_ranges)
    if addr:
        offsets['punchangle_x'] = addr

    addr = calibrate_value(scanner, 'FLASH DURATION', 'Normal=0:',
                           'Changed when flashed:', fmt='<f',
                           module_ranges=game_ranges)
    if addr:
        offsets['flash_duration'] = addr

    # ── Velocity ──────────────────────────────────────────────────────────────
    print(f"\n{C}{'──────────────────────────────────────────────────'}{X}")
    print(f'{B}{Y}  CALIBRATION: VELOCITY (SPEED){X}')
    print(f"{C}{'──────────────────────────────────────────────────'}{X}")
    print(f'  {D}[1] Normal Mode | [2] CE Mode (Auto-Detect){X}')
    v_mode = input(f'  {B}> {X}').strip()
    if v_mode == '2':
        addr = calibrate_ce(scanner, 'VELOCITY',
                            'Changed while running, Unchanged while idle.',
                            game_ranges)
    else:
        addr = calibrate_value(scanner, 'VELOCITY', 'Idle=0:', 'Running=Changed:',
                               fmt='<f', module_ranges=game_ranges)
    if addr:
        offsets['velocity'] = addr

    # ── View angles ───────────────────────────────────────────────────────────
    print(f"\n{C}{'──────────────────────────────────────────────────'}{X}")
    print(f'{B}{Y}  VIEWANGLE CALIBRATION{X}')
    print(f"{C}{'──────────────────────────────────────────────────'}{X}")
    print(f'  {C}[1]{X} Normal mode (Manual input)')
    print(f'  {C}[2]{X} CE mode (Auto Changed/Unchanged)')
    print(f'  {D}[skip]{X} Skip')
    va_mode = input(f'\n  {B}> {X}').strip().lower()

    if va_mode == '1':
        addr = calibrate_value(scanner, 'VIEWANGLE X (pitch)',
                               'Look straight, X~0:', 'Look UP! Value? (e.g. -30):',
                               fmt='<f', module_ranges=game_ranges, max_attempts=25)
        if addr:
            offsets['viewangle_x'] = addr
        addr = calibrate_value(scanner, 'VIEWANGLE Y (yaw)',
                               'Look North, Y value:', 'Turn RIGHT! New Y value?:',
                               fmt='<f', module_ranges=game_ranges, max_attempts=25)
        if addr:
            offsets['viewangle_y'] = addr

    elif va_mode == '2':
        for axis, axis_name, tip in [
            ('viewangle_x', 'VIEWANGLE X', 'look UP/DOWN'),
            ('viewangle_y', 'VIEWANGLE Y', 'turn LEFT/RIGHT'),
        ]:
            print(f'\n  {B}{Y}--- {axis_name} (CE MODE) ---{X}')
            print(f'  {C}[*] Scanning all float addresses...{X}')
            ce_scanner = MemScanner(handle)
            ce_scanner.results.clear()
            for base, size in game_ranges:
                data = ce_scanner.read_region(base, size)
                if not data:
                    continue
                for off in range(0, len(data) - 3, 4):
                    try:
                        v = struct.unpack_from('<f', data, off)[0]
                        if -500.0 < v < 500.0 and v != 0.0:
                            ce_scanner.results[base + off] = v
                    except Exception:
                        pass
            total = len(ce_scanner.results)
            print(f'  {D}  {total} float addresses found{X}')
            for rnd in range(1, 5):
                print(f'\n  {M}=== ROUND {rnd}/4 ==={X}')
                print(f'  {R}{B}>>> DON\'T TOUCH MOUSE! Stay still 5s... <<<{X}')
                for countdown in range(5, 0, -1):
                    sys.stdout.write(f'\r  {Y}{countdown}...{X}  ')
                    sys.stdout.flush()
                    time.sleep(1)
                for pass_num in range(3):
                    snap = {addr: rpm_float(handle, addr)
                            for addr in list(ce_scanner.results.keys())}
                    time.sleep(0.5)
                    keep = {addr: v for addr, v in snap.items()
                            if abs(rpm_float(handle, addr) - v) < 0.01}
                    ce_scanner.results = keep
                    sys.stdout.write(f'\r  {D}Unchanged pass {pass_num+1}: {len(keep)} left{X}   ')
                    sys.stdout.flush()
                print()
                move_sec = 30 if rnd == 1 else 15
                print(f'\n  {G}{B}>>> NOW MOVE MOUSE! ({tip}) {move_sec}s... <<<{X}')
                print(f'  {D}Move constantly, don\'t stop!{X}')
                end_time   = time.time() + move_sec
                pass_count = 0
                while time.time() < end_time:
                    remaining = int(end_time - time.time())
                    snap = {addr: rpm_float(handle, addr)
                            for addr in list(ce_scanner.results.keys())}
                    time.sleep(0.3)
                    keep = {addr: rpm_float(handle, addr)
                            for addr, v in snap.items()
                            if abs(rpm_float(handle, addr) - v) > 0.01}
                    if keep:
                        ce_scanner.results = keep
                    pass_count += 1
                    sys.stdout.write(f'\r  {C}[{remaining}s] Changed pass {pass_count}: '
                                     f'{len(ce_scanner.results)} left{X}   ')
                    sys.stdout.flush()
                print()
                print(f'  {D}Round {rnd} finished: {len(ce_scanner.results)} left{X}')
                q = input(f'  {W}Round finished. Enter to continue, \'ok\' to go live:{X} ').strip().lower()
                if q in ['ok', 'tamam', 'gec']:
                    break
            count = len(ce_scanner.results)
            print(f'\n  {G}[+] {count} addresses left!{X}')
            if count > 0:
                scanner.results = ce_scanner.results
                addrs = list(scanner.results.keys())
                if count == 1:
                    offsets[axis] = addrs[0]
                    print(f'  {G}[+] {axis_name}: 0x{addrs[0]:08X}{X}')
                else:
                    addr = calibrate_value(
                        scanner, axis_name, None, 'Change the value!',
                        fmt='<f', module_ranges=game_ranges,
                        first_val=rpm_float(handle, addrs[0]), max_attempts=25)
                    if addr:
                        offsets[axis] = addr

    # ── Position (for ESP/Aimbot) ─────────────────────────────────────────────
    print(f"\n{C}{'──────────────────────────────────────────────────'}{X}")
    print(f'{B}{Y}  POSITION CALIBRATION (for ESP/Aimbot){X}')
    print(f"{C}{'──────────────────────────────────────────────────'}{X}")
    print(f'  {D}Type \'cl_showpos 1\' in-game to see your coordinates.{X}')
    print(f'  {C}[1]{X} CE mode (idle/move automatic)')
    print(f'  {D}[skip]{X} Skip')
    pos_mode = input(f'\n  {B}> {X}').strip().lower()

    if pos_mode == '1':
        for axis, axis_name, tip in [
            ('pos_x', 'POSITION X', 'move LEFT/RIGHT'),
            ('pos_y', 'POSITION Y', 'move FORWARD/BACKWARD'),
            ('pos_z', 'POSITION Z', 'JUMP/CROUCH'),
        ]:
            print(f'\n  {B}{Y}--- {axis_name} (CE MODE) ---{X}')
            ax_skip = input(f'  {D}Press Enter to start, \'skip\' to skip: {X}').strip().lower()
            if ax_skip in ['skip', 's', 'atla']:
                continue

            ce_scanner = MemScanner(handle)
            ce_scanner.results.clear()
            print(f'  {D}  Scanning...{X}')
            scan_targets = game_ranges if game_ranges else ce_scanner.get_regions()

            for base, size in scan_targets:
                data = ce_scanner.read_region(base, size)
                if not data:
                    continue
                for off in range(0, len(data) - 3, 4):
                    try:
                        v = struct.unpack_from('<f', data, off)[0]
                        if -5000.0 < v < 5000.0 and v != 0.0:
                            ce_scanner.results[base + off] = v
                    except Exception:
                        pass

            if not ce_scanner.results:
                print(f'  {Y}[!] Not found in modules, scanning entire memory...{X}')
                for base, size in ce_scanner.get_regions():
                    data = ce_scanner.read_region(base, size)
                    if data:
                        for off in range(0, len(data) - 3, 4):
                            try:
                                v = struct.unpack_from('<f', data, off)[0]
                                if -8000.0 < v < 8000.0 and v != 0.0:
                                    ce_scanner.results[base + off] = v
                            except Exception:
                                pass

            print(f'  {D}  {len(ce_scanner.results)} float addresses found{X}')
            for rnd in range(1, 5):
                print(f'\n  {M}=== ROUND {rnd}/4 ==={X}')
                print(f'  {R}{B}>>> STAY STILL! 5s... <<<{X}')
                for cd in range(5, 0, -1):
                    sys.stdout.write(f'\r  {Y}{cd}...{X}  ')
                    sys.stdout.flush()
                    time.sleep(1)
                for pn in range(3):
                    snap = {a: rpm_float(handle, a) for a in list(ce_scanner.results.keys())}
                    time.sleep(0.5)
                    keep = {a: v for a, v in snap.items()
                            if abs(rpm_float(handle, a) - v) < 0.01}
                    ce_scanner.results = keep
                    sys.stdout.write(f'\r  {D}Unchanged {pn+1}: {len(keep)} left{X}   ')
                    sys.stdout.flush()
                print()
                ms = 30 if rnd == 1 else 15
                print(f'\n  {G}{B}>>> {tip.upper()}! {ms}s... <<<{X}')
                end_t = time.time() + ms
                while time.time() < end_t:
                    rem  = int(end_t - time.time())
                    snap = {a: rpm_float(handle, a) for a in list(ce_scanner.results.keys())}
                    time.sleep(0.3)
                    keep = {a: rpm_float(handle, a) for a, v in snap.items()
                            if abs(rpm_float(handle, a) - v) > 0.1}
                    if keep:
                        ce_scanner.results = keep
                    sys.stdout.write(f'\r  {C}[{rem}s] Changed: {len(ce_scanner.results)} left{X}   ')
                    sys.stdout.flush()
                print()
                print(f'  {D}Round {rnd}: {len(ce_scanner.results)} left{X}')
                q = input(f'  {W}Round finished. Enter to continue, \'ok\' to go live:{X} ').strip().lower()
                if q in ['ok', 'skip', 'continue']:
                    break
            count = len(ce_scanner.results)
            if count > 0:
                scanner.results = ce_scanner.results
                addr = calibrate_value(
                    scanner, axis_name, None, 'Move in-game!',
                    fmt='<f', module_ranges=game_ranges,
                    first_val=rpm_float(handle, list(ce_scanner.results.keys())[0]),
                    max_attempts=25)
                if addr:
                    offsets[axis] = addr

    # ── Entity list discovery via stride ──────────────────────────────────────
    if all(k in offsets for k in ['pos_x', 'pos_y', 'pos_z']):
        print(f"\n{C}{'──────────────────────────────────────────────────'}{X}")
        print(f'{B}{Y}  CALIBRATION: ENTITY LIST (PLAYERS){X}')
        print(f"{C}{'──────────────────────────────────────────────────'}{X}")
        print(f'  {D}Auto-discovering using coordinate patterns...{X}')

        px_addr = offsets['pos_x'][0] if isinstance(offsets['pos_x'], list) else offsets['pos_x']
        py_addr = offsets['pos_y'][0] if isinstance(offsets['pos_y'], list) else offsets['pos_y']
        pz_addr = offsets['pos_z'][0] if isinstance(offsets['pos_z'], list) else offsets['pos_z']

        if py_addr == px_addr + 4 and pz_addr == px_addr + 8:
            print(f'  {G}[+] X,Y,Z consecutive! (offset +0, +4, +8){X}')
            pos_base = px_addr
            print(f'  {C}[*] Searching for entity stride...{X}')
            print(f'  {D}You need at least 1 bot/player in-game for this!{X}')
            my_x = rpm_float(handle, pos_base)
            my_y = rpm_float(handle, pos_base + 4)
            my_z = rpm_float(handle, pos_base + 8)
            found_stride = None
            for stride in range(256, 2048, 4):
                valid_ents = 0
                for i in range(1, 33):
                    ent_base = pos_base + stride * i
                    ex = rpm_float(handle, ent_base)
                    ey = rpm_float(handle, ent_base + 4)
                    ez = rpm_float(handle, ent_base + 8)
                    if ((abs(ex) > 1 or abs(ey) > 1 or abs(ez) > 1)
                            and -10000 < ex < 10000
                            and -10000 < ey < 10000
                            and -10000 < ez < 10000):
                        valid_ents += 1
                if valid_ents >= 1:
                    ent1 = pos_base + stride
                    e1x  = rpm_float(handle, ent1)
                    e1y  = rpm_float(handle, ent1 + 4)
                    dist = math.sqrt((e1x - my_x) ** 2 + (e1y - my_y) ** 2)
                    if dist > 10:
                        found_stride = stride
                        print(f'  {G}{B}[+] STRIDE FOUND: 0x{stride:04X} ({stride} bytes){X}')
                        print(f'  {D}  {valid_ents} entities verified{X}')
                        break
            if found_stride:
                offsets['entity_base']   = pos_base
                offsets['entity_stride'] = found_stride
                print(f'\n  {W}Entities found:{X}')
                for i in range(0, 33):
                    eb  = pos_base + found_stride * i
                    ex  = rpm_float(handle, eb)
                    ey  = rpm_float(handle, eb + 4)
                    ez  = rpm_float(handle, eb + 8)
                    if abs(ex) > 1 or abs(ey) > 1 or abs(ez) > 1:
                        dist = math.sqrt((ex - my_x) ** 2 + (ey - my_y) ** 2 + (ez - my_z) ** 2)
                        tag  = f'{G}[SELF]{X}' if i == 0 else f'{Y}[{dist:.0f}u]{X}'
                        print(f'    {C}#{i:02}{X} X:{ex:.0f} Y:{ey:.0f} Z:{ez:.0f} {tag}')
            else:
                print(f'  {Y}[!] Stride not found. Add bots and try again.{X}')
        else:
            print(f'  {Y}[!] X,Y,Z are not consecutive. Manual adjustment required.{X}')
            print(f'  {D}X: 0x{px_addr:08X}, Y: 0x{py_addr:08X}, Z: 0x{pz_addr:08X}{X}')

    # ── Save ──────────────────────────────────────────────────────────────────
    with open(OFFSETS_FILE, 'w') as f:
        json.dump(offsets, f, indent=2)

    print(f"\n{G}{'══════════════════════════════════════════════════'}{X}")
    print(f'{G}{B}  CALIBRATION COMPLETED!{X}')
    all_keys = ['health_direct', 'armor_direct', 'force_jump', 'force_attack',
                'ground_flag', 'crosshair_id', 'viewangle_x', 'viewangle_y',
                'pos_x', 'pos_y', 'pos_z', 'entity_base', 'entity_stride']
    found = sum(1 for k in all_keys if k in offsets)
    print(f'{G}  {found}/{len(all_keys)} offsets found and saved.{X}')
    print(f"{G}{'══════════════════════════════════════════════════'}{X}")
    return offsets

# ── MAIN ─────────────────────────────────────────────────────────────────────

def header(title):
    print(f'\n{C}+{"=" * 54}+')
    print(f'|  {B}{title:<52}{X}{C}|')
    print(f'+{"=" * 54}+{X}\n')

def main():
    # Enable ANSI escape codes on Windows 10+
    try:
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

    while True:
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
            header('ECLIPSE CS 1.6 OFFSET DUMPER')
            print(f'  {C}Searching for hl.exe...{X}')
            while not find_pid('hl.exe'):
                time.sleep(1)
            pid = find_pid('hl.exe')
            print(f'  {G}PID: {pid}{X}')

            handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not handle:
                print(f'  {R}Run as Administrator.{X}')
                input()
                return

            modules = get_modules(pid)
            print(f'  {G}{len(modules)} modules loaded{X}')

            offsets = {}
            if os.path.exists(OFFSETS_FILE):
                with open(OFFSETS_FILE) as f:
                    offsets = json.load(f)

            os.system('cls' if os.name == 'nt' else 'clear')
            header('ECLIPSE CS 1.6 OFFSET DUMPER')

            all_keys = [
                'health_direct', 'armor_direct', 'team', 'is_alive',
                'force_jump', 'force_attack', 'ground_flag', 'crosshair_id',
                'flash_alpha', 'flash_duration', 'fov_value',
                'viewangle_x', 'viewangle_y', 'punchangle_x', 'punchangle_y',
                'pos_x', 'pos_y', 'pos_z', 'velocity', 'fall_velocity',
                'max_speed', 'water_level', 'button_pressed',
                'weapon_id', 'clip_ammo', 'reserve_ammo',
                'entity_base', 'entity_stride', 'bone_matrix',
            ]
            for k in all_keys:
                v = offsets.get(k)
                if v:
                    if isinstance(v, list):
                        s = f'{G}+ {len(v)}{X}'
                    elif isinstance(v, int):
                        s = f'{G}+ 0x{v:08X}{X}'
                    else:
                        s = f'{G}+{X}'
                else:
                    s = f'{R}-{X}'
                print(f'    {s} {D}{k}{X}')

            print(f'\n  {C}[1]{X} Full Scan')
            print(f'  {C}[2]{X} Single Offset Scan')
            print(f'  {C}[3]{X} Reset All Offsets')
            print(f'  {C}[4]{X} Live Watch')
            print(f'  {C}[5]{X} List Offsets')
            print(f'  {C}[6]{X} Save to File')
            print(f'  {C}[7]{X} Create Signatures (Prepare Auto-Update)')
            print(f'  {C}[8]{X} Scan with Signatures (Auto-Update)')
            print(f'  {C}[9]{X} Custom Scan (Int/Float)')
            print(f'  {C}[q]{X} Exit')
            ch = input(f'\n  {B}> {X}').strip().lower()

            if ch == '1':
                offsets = run_calibration(handle, modules)

            elif ch == '2':
                print(f'\n  {W}Offset selection:{X}')
                for i, k in enumerate(all_keys):
                    print(f'    {C}[{i}]{X} {k}')
                pick = input(f'\n  {B}> {X}').strip()
                try:
                    idx = int(pick)
                    key = all_keys[idx]
                    scanner     = MemScanner(handle)
                    game_ranges = []
                    for name, base, size in modules:
                        if name.lower() == 'client.dll':
                            game_ranges.append((base, size))
                        if name.lower() in ['hw.dll', 'engine.dll', 'sw.dll']:
                            game_ranges.append((base, size))
                    if not game_ranges:
                        print(f'  {Y}[!] Modules not found, scanning all memory...{X}')
                        game_ranges = None

                    float_keys = [
                        'health_direct', 'flash_alpha', 'flash_duration', 'fov_value',
                        'viewangle_x', 'viewangle_y', 'punchangle_x', 'punchangle_y',
                        'pos_x', 'pos_y', 'pos_z', 'velocity', 'fall_velocity', 'max_speed',
                    ]
                    fmt = '<f' if key in float_keys else '<i'
                    questions = {
                        'health_direct':  ('Current Health:',        'Updated Health:'),
                        'armor_direct':   ('Current Armor:',         'Updated Armor:'),
                        'team':           ('Team? (1:T, 2:CT):',     'Updated Team:'),
                        'is_alive':       ('Alive=1, Dead=0:',       'Did you die? Type 0:'),
                        'weapon_id':      ('Weapon ID 1:',           'Weapon ID 2:'),
                        'clip_ammo':      ('Current Ammo:',          'Shoot, remaining ammo:'),
                        'reserve_ammo':   ('Reserve ammo:',          'Spend/Buy, remaining:'),
                        'punchangle_x':   ('Idle 0:',                'Shooting ?:'),
                        'flash_duration': ('Normal=0:',              'Flashed ?:'),
                        'velocity':       ('Idle 0:',                'Running ?:'),
                        'max_speed':      ('Max speed 250:',         'Updated ?:'),
                        'water_level':    ('Dry=0:',                 'In water ?:'),
                        'button_pressed': ('None=0:',                'Space pressed ?:'),
                        'ground_flag':    ('On Ground=1:',           'In Air=0:'),
                        'crosshair_id':   ('Empty=0:',               'Aiming at ID (1-32):'),
                    }
                    q1, q2 = questions.get(key, ('Initial value:', 'New value:'))
                    addr = calibrate_value(scanner, key, q1, q2, fmt=fmt,
                                           module_ranges=game_ranges)
                    if addr:
                        offsets[key] = addr
                        if key == 'health_direct':
                            offsets['health_is_float'] = (fmt == '<f')
                        with open(OFFSETS_FILE, 'w') as f:
                            json.dump(offsets, f, indent=2)
                        print(f'\n  {G}[+] {key} successfully calibrated!{X}')
                        a_show = addr[0] if isinstance(addr, list) else addr
                        print(f'  {D}Address: 0x{a_show:08X}{X}')
                        input(f'\n  {W}Press Enter to continue...{X}')
                except Exception as e:
                    print(f'  {R}Error: {e}{X}')
                    time.sleep(2)

            elif ch == '3':
                if os.path.exists(OFFSETS_FILE):
                    os.remove(OFFSETS_FILE)
                    print(f'  {G}[+] Offsets reset.{X}')
                    offsets = {}
                    time.sleep(1)

            elif ch == '4':
                print(f'\n  {D}ESC=exit{X}')
                while True:
                    line = '  '
                    for k in all_keys:
                        v = offsets.get(k)
                        if not v:
                            continue
                        a = v[0] if isinstance(v, list) else v
                        if not isinstance(a, int):
                            continue
                        fk = ['health_direct', 'flash_alpha', 'fov_value',
                              'viewangle_x', 'viewangle_y', 'pos_x', 'pos_y', 'pos_z']
                        if k in fk:
                            val_v = rpm_float(handle, a)
                            line += f'{D}{k[:4]}:{Y}{val_v:.1f}{X} '
                        else:
                            line += f'{D}{k[:4]}:{Y}{rpm_int(handle, a)}{X} '
                    line = line.ljust(100)
                    sys.stdout.write(f'\r{line}')
                    sys.stdout.flush()
                    time.sleep(0.1)
                    if msvcrt.kbhit() and ord(msvcrt.getch()) == 27:
                        break
                print()

            elif ch == '5':
                print(f'\n  {W}SAVED OFFSETS:{X}')
                for k, v in offsets.items():
                    if isinstance(v, list):
                        print(f'  {G}✓{X} {D}{k}: {len(v)} addresses{X}')
                    elif isinstance(v, int):
                        print(f'  {G}✓{X} {D}{k}: 0x{v:08X}{X}')
                    else:
                        print(f'  {G}✓{X} {D}{k}: {v}{X}')
                input(f'\n  {D}Press Enter to continue...{X}')

            elif ch == '6':
                with open(OFFSETS_FILE, 'w') as f:
                    json.dump(offsets, f, indent=2)
                print(f'  {G}[+] Offsets saved to {OFFSETS_FILE}!{X}')
                time.sleep(1.5)

            elif ch == '7':
                if not offsets:
                    print(f'  {R}[!] No offsets found. Scan first!{X}')
                    time.sleep(1.5)
                    continue
                print(f'\n  {C}[*] Generating signatures (this may take a while)...{X}')
                signatures = {}
                keys_to_sig = [k for k, v in offsets.items()
                               if not k.endswith('_is_float') and not k.startswith('entity_')]
                total_keys = len(keys_to_sig)
                for i, k in enumerate(keys_to_sig):
                    v       = offsets[k]
                    percent = int(i / total_keys * 100)
                    sys.stdout.write(f'\r  {C}[%{percent}] Processing {D}{k}...{X}'.ljust(60))
                    sys.stdout.flush()
                    addrs = v if isinstance(v, list) else [v]
                    sigs  = []
                    for a in addrs:
                        if isinstance(a, int):
                            sig = create_signature(handle, modules, a)
                            if sig:
                                sigs.append(sig)
                    if sigs:
                        signatures[k] = sigs
                        orig_addr = addrs[0]
                        sys.stdout.write(f'\n    {G}✓{X} {D}{k} (0x{orig_addr:08X}): '
                                         f'{len(sigs)} signatures generated.{X}\n')
                    else:
                        sys.stdout.write(f'\n    {R}✗{X} {D}{k}: No code references found.{X}\n')
                    sys.stdout.flush()
                if signatures:
                    with open(SIGS_FILE, 'w') as f:
                        json.dump(signatures, f, indent=2)
                    print(f'\n  {G}[+] 100%! {len(signatures)} signatures saved to {SIGS_FILE}!{X}')
                else:
                    print(f'  {R}[!] No signatures could be generated.{X}')
                input(f'\n  {D}Press Enter for Main Menu...{X}')

            elif ch == '8':
                if not os.path.exists(SIGS_FILE):
                    print(f'  {R}[!] Signature file not found. Do [7] first!{X}')
                    time.sleep(1.5)
                    continue
                with open(SIGS_FILE) as f:
                    signatures = json.load(f)
                print(f'\n  {C}[*] Scanning patterns (BRUTE FORCE)...{X}')
                new_offsets = {}
                all_regions = get_all_memory_regions(handle)
                print(f'  {D}Total memory regions to scan: {len(all_regions)}{X}')
                sig_keys  = list(signatures.keys())
                total_sigs = len(sig_keys)
                for i, k in enumerate(sig_keys):
                    sig_list = signatures[k]
                    percent  = int(i / total_sigs * 100)
                    sys.stdout.write(f'\r  {C}[%{percent}] Scouring entire memory for {D}{k}...{X}'.ljust(70))
                    sys.stdout.flush()
                    found_addrs = []
                    for sig in sig_list:
                        matches = find_pattern_in_memory(handle, all_regions, sig['pat'])
                        if not matches:
                            continue
                        for m_addr in matches:
                            target_code_addr = m_addr + sig['off']
                            buf = ctypes.create_string_buffer(4)
                            if kernel32.ReadProcessMemory(handle,
                                                          ctypes.c_void_p(target_code_addr),
                                                          buf, 4, None):
                                new_addr = struct.unpack('<I', buf.raw)[0]
                                if 65536 < new_addr < 2147483647:
                                    found_addrs.append(new_addr)
                                    break
                    if found_addrs:
                        new_offsets[k] = found_addrs[0] if len(found_addrs) == 1 else found_addrs
                        disp = new_offsets[k] if isinstance(new_offsets[k], int) else new_offsets[k][0]
                        sys.stdout.write(f'\n    {G}✓{X} {D}{k}: 0x{disp:08X}{X}\n')
                    else:
                        sys.stdout.write(f'\n    {R}✗{X} {D}{k}: Not Found!{X}\n')
                    sys.stdout.flush()
                    time.sleep(0.05)
                if new_offsets:
                    for k, v in offsets.items():
                        if k not in new_offsets:
                            new_offsets[k] = v
                    offsets = new_offsets
                    with open(OFFSETS_FILE, 'w') as f:
                        json.dump(offsets, f, indent=2)
                    print(f'\n  {G}[+] 100%! {len(new_offsets)} offsets updated!{X}')
                else:
                    print(f'  {R}[!] No patterns matched.{X}')
                input(f'\n  {D}Press Enter for Main Menu...{X}')

            elif ch == '9':
                print(f'\n  {B}{Y}--- CUSTOM SCAN ---{X}')
                t_type = input(f'  {C}[1]{X} Integer (Whole Number)\n'
                               f'  {C}[2]{X} Float (Decimal)\n  > ').strip()
                fmt  = '<f' if t_type == '2' else '<i'
                name = input('  Offset Name (e.g. gravity): ').strip()
                v1   = input('  Initial Value: ').strip()
                if v1:
                    scanner = MemScanner(handle)
                    addr    = calibrate_value(scanner, name, None, 'New Value?',
                                             fmt=fmt,
                                             first_val=float(v1) if t_type == '2' else int(v1))
                    if addr:
                        offsets[name] = addr
                        with open(OFFSETS_FILE, 'w') as f:
                            json.dump(offsets, f, indent=2)

            elif ch == 'q':
                kernel32.CloseHandle(handle)
                break

        except Exception as e:
            print(f'\n{R}[!] {e}{X}')
            try:
                input()
            except EOFError:
                pass

if __name__ == '__main__':
    main()
