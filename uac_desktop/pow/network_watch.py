"""Notifications for the physical network carrying a Windows POW session."""

from __future__ import annotations

import ctypes
import os
import threading


class NetworkNotifications:
    """Keep Windows callbacks alive until their registrations are canceled."""

    def __init__(self, changed: threading.Event) -> None:
        self._handles: list[ctypes.c_void_p] = []
        if os.name != "nt":
            return
        api = ctypes.WinDLL("iphlpapi")
        callback_type = ctypes.WINFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int)
        self._callback = callback_type(lambda *_: changed.set())
        self._cancel = api.CancelMibChangeNotify2
        self._cancel.argtypes = (ctypes.c_void_p,)
        self._cancel.restype = ctypes.c_ulong
        try:
            for notify in (api.NotifyIpInterfaceChange, api.NotifyRouteChange2):
                notify.argtypes = (
                    ctypes.c_ushort, callback_type, ctypes.c_void_p,
                    ctypes.c_ubyte, ctypes.POINTER(ctypes.c_void_p),
                )
                notify.restype = ctypes.c_ulong
                handle = ctypes.c_void_p()
                error = notify(0, self._callback, None, 0, ctypes.byref(handle))
                if error:
                    raise ctypes.WinError(error)
                self._handles.append(handle)
        except OSError:
            self.close()
            raise

    def close(self) -> None:
        for handle in self._handles:
            self._cancel(handle)
        self._handles.clear()
