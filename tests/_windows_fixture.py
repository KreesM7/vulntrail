"""Create user-owned test objects even on elevated Windows CI workers.

Only the current test process's default owner changes, then is restored. No
privilege, DACL, existing file owner, or production ownership check is changed.
"""

from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import os


@contextmanager
def user_owned_creation():
    if os.name != "nt":
        yield
        return
    from vulntrail.response import _winapi

    kernel, security = _winapi()
    security.SetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    security.SetTokenInformation.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not security.OpenProcessToken(kernel.GetCurrentProcess(), 0x88, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())

    def query(kind):
        length = wintypes.DWORD()
        security.GetTokenInformation(token, kind, None, 0, ctypes.byref(length))
        buffer = ctypes.create_string_buffer(length.value)
        if not security.GetTokenInformation(token, kind, buffer, length, ctypes.byref(length)):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer

    def set_owner(value):
        if not security.SetTokenInformation(token, 4, value, ctypes.sizeof(ctypes.c_void_p)):
            raise ctypes.WinError(ctypes.get_last_error())

    try:
        original = query(4)
        user = query(1)
        user_owner = ctypes.c_void_p(ctypes.cast(user, ctypes.POINTER(ctypes.c_void_p))[0])
        set_owner(ctypes.byref(user_owner))
        try:
            yield
        finally:
            set_owner(original)
    finally:
        kernel.CloseHandle(token)
