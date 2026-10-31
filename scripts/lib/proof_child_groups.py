"""Pinned-group kernel observations; caller retains an unreaped Popen leader.

Membership oracle extracted unchanged from prepare-preflight-shell-tools.sh.
Darwin waitid fallback ABI: SDK sys/wait.h, sys/signal.h and sys/_types.h;
LP64 siginfo_t, P_PID=1, WNOHANG=1, WEXITED=4, WNOWAIT=0x20.
No SIGCHLD-only hint is accepted as evidence of an exited leader.
"""
import ctypes
import os
import signal
import sys
import time

LIBPROC = None
def group_other_members(leader):
    # Listed group members other than the pinned leader; raises RuntimeError
    # whenever the listing cannot be read completely.
    global LIBPROC
    if sys.platform != 'darwin':
        raise RuntimeError('group membership evidence unavailable')
    import ctypes
    if LIBPROC is None:
        try:
            LIBPROC = ctypes.CDLL('libproc.dylib', use_errno=True)
        except OSError as error:
            raise RuntimeError('group membership evidence unavailable') from error
        LIBPROC.proc_listpids.restype = ctypes.c_int
        LIBPROC.proc_listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
    ctypes.set_errno(0)
    size = LIBPROC.proc_listpids(2, leader, None, 0)
    if size <= 0 or size > 65536 * 4 or size % 4 or ctypes.get_errno() != 0:
        raise RuntimeError('group membership evidence unreadable')
    listing = ctypes.create_string_buffer(size)
    ctypes.set_errno(0)
    written = LIBPROC.proc_listpids(2, leader, listing, size)
    if written <= 0 or written >= size or written % 4 or ctypes.get_errno() != 0:
        raise RuntimeError('group membership evidence unreadable')
    pids = [int.from_bytes(listing.raw[index:index + 4], 'little') for index in range(0, written, 4)]
    if leader not in pids:
        raise RuntimeError('group membership listing missing the pinned leader')
    return [pid for pid in pids if pid != leader]


class Sigval(ctypes.Union):
    _fields_ = [("sival_int", ctypes.c_int), ("sival_ptr", ctypes.c_void_p)]


class DarwinSiginfo(ctypes.Structure):
    _fields_ = [("si_signo", ctypes.c_int), ("si_errno", ctypes.c_int),
                ("si_code", ctypes.c_int), ("si_pid", ctypes.c_int32),
                ("si_uid", ctypes.c_uint32), ("si_status", ctypes.c_int),
                ("si_addr", ctypes.c_void_p), ("si_value", Sigval),
                ("si_band", ctypes.c_long), ("__pad", ctypes.c_ulong * 7)]


def leader_exited_unreaped(leader):
    native = getattr(os, "waitid", None)
    if callable(native):
        value = native(os.P_PID, leader, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if value is None:
            return False
        if value.si_pid != leader or value.si_code not in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED):
            raise RuntimeError("unreaped leader exit evidence differs")
        return True
    if (sys.platform != "darwin" or ctypes.sizeof(ctypes.c_void_p) != 8
            or ctypes.sizeof(ctypes.c_long) != 8 or ctypes.sizeof(ctypes.c_int) != 4
            or ctypes.sizeof(DarwinSiginfo) != 104):
        raise RuntimeError("strict nonreaping exit evidence unavailable")
    try:
        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        waitid = libc.waitid
        waitid.argtypes = [ctypes.c_int, ctypes.c_uint32, ctypes.POINTER(DarwinSiginfo), ctypes.c_int]
        waitid.restype = ctypes.c_int
        info = DarwinSiginfo()
        ctypes.set_errno(0)
        result = waitid(1, leader, ctypes.byref(info), 0x01 | 0x04 | 0x20)
        if result != 0 or ctypes.get_errno() != 0:
            raise RuntimeError("native nonreaping exit observation failed")
    except (OSError, AttributeError) as error:
        raise RuntimeError("native nonreaping exit observation unavailable") from error
    if info.si_pid == 0 and info.si_signo == 0 and info.si_code == 0:
        return False
    if info.si_pid != leader or info.si_signo != signal.SIGCHLD or info.si_code not in (1, 2, 3):
        raise RuntimeError("native nonreaping leader exit evidence differs")
    return True


def confirm_ended_group(leader, timeout=2.0):
    """Positive exit+complete leader-only census before caller releases PID."""
    until = time.monotonic() + timeout
    while True:
        if leader_exited_unreaped(leader):
            other = group_other_members(leader)
            if not other:
                return {"leader": leader, "leader_exited_unreaped": True, "members": [leader]}
        if time.monotonic() >= until:
            raise RuntimeError("owned group cleanup remains unconfirmed")
        time.sleep(0.05)
