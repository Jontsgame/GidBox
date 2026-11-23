import ctypes
from ctypes import wintypes
from datetime import datetime
import json
from pathlib import Path
import sys

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Konstanten aus winbase.h / minwinbase.h
DEBUG_ONLY_THIS_PROCESS = 0x00000002
CREATE_NEW_CONSOLE = 0x00000010
INFINITE = 0xFFFFFFFF
DBG_CONTINUE = 0x00010002

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.BYTE)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE),
        ("lpBaseOfDll", wintypes.LPVOID),
        ("dwDebugInfoFileOffset", wintypes.DWORD),
        ("nDebugInfoSize", wintypes.DWORD),
        ("lpImageName", wintypes.LPVOID),
        ("fUnicode", wintypes.WORD),
    ]


class DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("RawBytes", ctypes.c_byte * 160),
    ]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", DEBUG_EVENT_UNION),
    ]


kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.BOOL,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW),
    ctypes.POINTER(PROCESS_INFORMATION),
]
kernel32.CreateProcessW.restype = wintypes.BOOL

kernel32.WaitForDebugEvent.argtypes = [
    ctypes.POINTER(DEBUG_EVENT),
    wintypes.DWORD,
]
kernel32.WaitForDebugEvent.restype = wintypes.BOOL

kernel32.ContinueDebugEvent.argtypes = [
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
]
kernel32.ContinueDebugEvent.restype = wintypes.BOOL


def log_event(log_file: Path, payload: dict):
    payload["ts"] = datetime.now().isoformat(timespec="milliseconds")
    line = json.dumps(payload, ensure_ascii=False)
    print(line)
    with log_file.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def run_trace(target_exe: str, log_path: str = "trace_log.jsonl"):
    log_file = Path(log_path)
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()

    flags = DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE
    ok = kernel32.CreateProcessW(
        target_exe, None, None, None, False, flags, None, None, si, pi
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    log_event(
        log_file,
        {
            "event": "process_started",
            "exe": target_exe,
            "pid": pi.dwProcessId,
        },
    )

    try:
        while True:
            ev = DEBUG_EVENT()
            if not kernel32.WaitForDebugEvent(ctypes.byref(ev), INFINITE):
                break

            code = ev.dwDebugEventCode

            if code == LOAD_DLL_DEBUG_EVENT:
                dll_info = ev.u.LoadDll
                base_addr = (
                    hex(dll_info.lpBaseOfDll) if dll_info.lpBaseOfDll else None
                )
                log_event(
                    log_file,
                    {
                        "event": "load_dll",
                        "pid": ev.dwProcessId,
                        "base_address": base_addr,
                        "file_handle": int(dll_info.hFile)
                        if dll_info.hFile
                        else 0,
                    },
                )
                if dll_info.hFile:
                    kernel32.CloseHandle(dll_info.hFile)

            elif code == EXIT_PROCESS_DEBUG_EVENT:
                log_event(
                    log_file, {"event": "process_exited", "pid": ev.dwProcessId}
                )
                kernel32.ContinueDebugEvent(
                    ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE
                )
                break

            kernel32.ContinueDebugEvent(
                ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE
            )
    finally:
        if pi.hProcess:
            kernel32.CloseHandle(pi.hProcess)
        if pi.hThread:
            kernel32.CloseHandle(pi.hThread)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Nutzung: python trace_process.py <pfad_zur_exe>")
        sys.exit(1)
    run_trace(sys.argv[1])
