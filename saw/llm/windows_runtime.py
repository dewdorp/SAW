"""Capability-free Windows LPAC and bounded Job for local CPU inference.

Adapted from the existing Codex Windows native boundary. Only the native
launch and private-runtime sealing primitives are retained, without PCAP
policy, parser, application, or model-approval dependencies.
"""
import ctypes
import ctypes as c
import math
import os
import shutil
import subprocess
import threading
import time
from contextlib import contextmanager
from ctypes import wintypes
from ctypes import wintypes as w
from pathlib import Path
from uuid import uuid4

from saw.llm.model_packs import safe_path, verify_file


def _path(value):
    path = safe_path(value)
    if not path.is_file():
        raise ValueError("cpu_artifact_missing")
    return path


def _verify_file(path, pin, check):
    verify_file(path, pin, path.stat().st_size, check)


class NativeError(OSError):
    """Only operation and OS error code; never source bytes, credentials or argv."""


class STARTUPINFOW(c.Structure):
    _fields_ = [('cb', w.DWORD), ('lpReserved', w.LPWSTR), ('lpDesktop', w.LPWSTR), ('lpTitle', w.LPWSTR),
                ('dwX', w.DWORD), ('dwY', w.DWORD), ('dwXSize', w.DWORD), ('dwYSize', w.DWORD),
                ('dwXCountChars', w.DWORD), ('dwYCountChars', w.DWORD), ('dwFillAttribute', w.DWORD),
                ('dwFlags', w.DWORD), ('wShowWindow', w.WORD), ('cbReserved2', w.WORD),
                ('lpReserved2', c.c_void_p), ('hStdInput', w.HANDLE), ('hStdOutput', w.HANDLE), ('hStdError', w.HANDLE)]


class STARTUPINFOEXW(c.Structure):
    _fields_ = [('StartupInfo', STARTUPINFOW), ('lpAttributeList', c.c_void_p)]


class PROCESS_INFORMATION(c.Structure):
    _fields_ = [('hProcess', w.HANDLE), ('hThread', w.HANDLE), ('dwProcessId', w.DWORD), ('dwThreadId', w.DWORD)]


class SECURITY_CAPABILITIES(c.Structure):
    _fields_ = [('AppContainerSid', c.c_void_p), ('Capabilities', c.c_void_p), ('CapabilityCount', w.DWORD), ('Reserved', w.DWORD)]


class SID_AND_ATTRIBUTES(c.Structure):
    _fields_ = [('Sid', c.c_void_p), ('Attributes', w.DWORD)]


class GENERIC_MAPPING(c.Structure):
    _fields_ = [('GenericRead', w.DWORD), ('GenericWrite', w.DWORD), ('GenericExecute', w.DWORD), ('GenericAll', w.DWORD)]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(c.Structure):
    _fields_ = [('PerProcessUserTimeLimit', c.c_longlong), ('PerJobUserTimeLimit', c.c_longlong),
                ('LimitFlags', w.DWORD), ('MinimumWorkingSetSize', c.c_size_t), ('MaximumWorkingSetSize', c.c_size_t),
                ('ActiveProcessLimit', w.DWORD), ('Affinity', c.c_size_t), ('PriorityClass', w.DWORD), ('SchedulingClass', w.DWORD)]


class IO_COUNTERS(c.Structure):
    _fields_ = [(name, c.c_ulonglong) for name in ('ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
                                                 'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(c.Structure):
    _fields_ = [('BasicLimitInformation', JOBOBJECT_BASIC_LIMIT_INFORMATION), ('IoInfo', IO_COUNTERS),
                ('ProcessMemoryLimit', c.c_size_t), ('JobMemoryLimit', c.c_size_t),
                ('PeakProcessMemoryUsed', c.c_size_t), ('PeakJobMemoryUsed', c.c_size_t)]


class PROCESS_MEMORY_COUNTERS_EX(c.Structure):
    _fields_ = [('cb', w.DWORD), ('PageFaultCount', w.DWORD)] + [
        (name, c.c_size_t) for name in ('PeakWorkingSetSize', 'WorkingSetSize',
        'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage',
        'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage', 'PrivateUsage')]


def _job_cpu_limit(max_seconds, max_cpu_seconds):
    # Historical PCAP budget is unchanged. CPU inference explicitly opts in.
    seconds = max_seconds * .1 if max_cpu_seconds is None else max_cpu_seconds
    if type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 < seconds <= 3600:
        raise ValueError('sandbox_cpu_budget_invalid')
    return max(1, int(seconds * 10_000_000))


def _api():
    if os.name != 'nt':
        raise NativeError('WINDOWS_SANDBOX_REQUIRED')
    kernel = c.WinDLL('kernel32', use_last_error=True)
    user = c.WinDLL('userenv', use_last_error=True)
    adv = c.WinDLL('advapi32', use_last_error=True)
    declarations = {
        'CreateJobObjectW': ([c.c_void_p, w.LPCWSTR], w.HANDLE),
        'SetInformationJobObject': ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD], w.BOOL),
        'QueryInformationJobObject': ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p], w.BOOL),
        'AssignProcessToJobObject': ([w.HANDLE, w.HANDLE], w.BOOL),
        'IsProcessInJob': ([w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)], w.BOOL),
        'TerminateProcess': ([w.HANDLE, w.UINT], w.BOOL),
        'TerminateJobObject': ([w.HANDLE, w.UINT], w.BOOL),
        'CloseHandle': ([w.HANDLE], w.BOOL),
        'ResumeThread': ([w.HANDLE], w.DWORD),
        'WaitForSingleObject': ([w.HANDLE, w.DWORD], w.DWORD),
        'GetExitCodeProcess': ([w.HANDLE, c.POINTER(w.DWORD)], w.BOOL),
        'GetProcessTimes': ([w.HANDLE, c.c_void_p, c.c_void_p, c.c_void_p, c.c_void_p], w.BOOL),
        'K32GetProcessMemoryInfo': ([w.HANDLE, c.POINTER(PROCESS_MEMORY_COUNTERS_EX), w.DWORD], w.BOOL),
        'InitializeProcThreadAttributeList': ([c.c_void_p, w.DWORD, w.DWORD, c.POINTER(c.c_size_t)], w.BOOL),
        'UpdateProcThreadAttribute': ([c.c_void_p, w.DWORD, c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p, c.c_void_p], w.BOOL),
        'DeleteProcThreadAttributeList': ([c.c_void_p], None),
        'CreateProcessW': ([w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p, w.BOOL, w.DWORD, c.c_void_p,
                            w.LPCWSTR, c.POINTER(STARTUPINFOEXW), c.POINTER(PROCESS_INFORMATION)], w.BOOL),
        'LocalFree': ([c.c_void_p], c.c_void_p),
        'GetCurrentProcess': ([], w.HANDLE),
    }
    for name, (args, restype) in declarations.items():
        getattr(kernel, name).argtypes = args
        getattr(kernel, name).restype = restype
    user.CreateAppContainerProfile.argtypes = [w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, c.c_void_p, w.DWORD, c.POINTER(c.c_void_p)]
    user.CreateAppContainerProfile.restype = c.c_long
    user.DeleteAppContainerProfile.argtypes = [w.LPCWSTR]
    user.DeleteAppContainerProfile.restype = c.c_long
    user.GetAppContainerFolderPath.argtypes = [w.LPCWSTR, c.POINTER(w.LPWSTR)]
    user.GetAppContainerFolderPath.restype = c.c_long
    adv.FreeSid.argtypes = [c.c_void_p]
    adv.FreeSid.restype = c.c_void_p
    adv.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(w.LPWSTR)]
    adv.ConvertSidToStringSidW.restype = w.BOOL
    adv.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    adv.OpenProcessToken.restype = w.BOOL
    adv.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
    adv.GetTokenInformation.restype = w.BOOL
    adv.EqualSid.argtypes = [c.c_void_p, c.c_void_p]
    adv.EqualSid.restype = w.BOOL
    adv.GetSidSubAuthorityCount.argtypes = [c.c_void_p]
    adv.GetSidSubAuthorityCount.restype = c.POINTER(w.BYTE)
    adv.GetSidSubAuthority.argtypes = [c.c_void_p, w.DWORD]
    adv.GetSidSubAuthority.restype = c.POINTER(w.DWORD)
    adv.DuplicateTokenEx.argtypes = [w.HANDLE, w.DWORD, c.c_void_p, c.c_int, c.c_int, c.POINTER(w.HANDLE)]
    adv.DuplicateTokenEx.restype = w.BOOL
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
    adv.AccessCheck.argtypes = [c.c_void_p, w.HANDLE, w.DWORD, c.POINTER(GENERIC_MAPPING), c.c_void_p,
                               c.POINTER(w.DWORD), c.POINTER(w.DWORD), c.POINTER(w.BOOL)]
    adv.AccessCheck.restype = w.BOOL
    return kernel, user, adv


def _check(result, operation):
    if not result:
        raise NativeError(f'{operation}:{c.get_last_error()}')


def windows_root():
    # Windows os.environ enumerates names in uppercase. The external runner may
    # intentionally omit environment variables; derive the OS path from Win32.
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.GetWindowsDirectoryW.argtypes = [w.LPWSTR, w.UINT]
    kernel.GetWindowsDirectoryW.restype = w.UINT
    value = c.create_unicode_buffer(32768)
    count = kernel.GetWindowsDirectoryW(value, len(value))
    if not 0 < count < len(value):
        raise NativeError('WINDOWS_DIRECTORY_LOOKUP_FAILED')
    return Path(value.value)


def _verify_lpac_access(kernel, adv, token):
    """Verify documented LPAC access semantics with real kernel AccessCheck.

    Class46 GetTokenInformation fails87 on observed build26200; do not infer LPAC
    from that undocumented output. LPAC must ignore ALL_APPLICATION_PACKAGES,
    and retain the OS ALL_RESTRICTED_APPLICATION_PACKAGES system-resource grant.
    """
    duplicate = w.HANDLE()
    _check(adv.DuplicateTokenEx(token, 8, None, 2, 2, c.byref(duplicate)), 'DUPLICATE_FOR_ACCESS_CHECK')
    try:
        observed = []
        for package_sid in ('S-1-15-2-1', 'S-1-15-2-2'):
            descriptor = c.c_void_p()
            _check(adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                f'O:WDG:WDD:(A;;0x1;;;WD)(A;;0x1;;;{package_sid})', 1, c.byref(descriptor), None), 'LPAC_PROBE_DESCRIPTOR')
            try:
                mapping = GENERIC_MAPPING(1, 2, 4, 7)
                privileges = c.create_string_buffer(1024)
                size, granted, access = w.DWORD(len(privileges)), w.DWORD(), w.BOOL()
                _check(adv.AccessCheck(descriptor, duplicate, 1, c.byref(mapping), privileges,
                                       c.byref(size), c.byref(granted), c.byref(access)), 'LPAC_KERNEL_ACCESS_CHECK')
                observed.append(bool(access.value))
            finally:
                kernel.LocalFree(descriptor)
        if observed != [False, True]:
            raise NativeError('LPAC_ACCESS_SEMANTICS_VERIFICATION_FAILED')
    finally:
        kernel.CloseHandle(duplicate)


def _acl(path, sid, access, recursive=False, remove=False, deny=False, remove_deny=False):
    # Absolute OS executable; no PATH search, shell, elevation or global ACL edits.
    exe = windows_root() / 'System32' / 'icacls.exe'
    verb = '/remove:d' if remove_deny else '/remove:g' if remove else '/deny' if deny else '/grant'
    args = [str(exe), str(path), verb, f'*{sid}' if remove or remove_deny else f'*{sid}:{access}']
    if recursive:
        args.append('/T')
    result = subprocess.run([*args, '/Q'], capture_output=True, check=False,
                            timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise NativeError('SANDBOX_ACL_FAILED')


def launch_appcontainer(argv, *, engine_root, cwd, input_path=None, max_seconds=10,
                        max_memory_bytes=256*1024**2, max_output_bytes=8*1024**2,
                        max_cpu_seconds=None, should_cancel=lambda: False, heartbeat=lambda: None,
                        collect_process_metrics=False, read_only_cwd=False):
    """Internal native primitive. Callers validate/pin argv and all engine files first.

    A unique capability-free token is checked while suspended; the process is
    assigned to a kill-on-close, single-process, CPU/memory-limited JobObject
    before its first instruction. Only three explicit stdio handles are inherited.
    """
    cpu_limit = _job_cpu_limit(max_seconds, max_cpu_seconds)
    engine_root, cwd = safe_path(engine_root), safe_path(cwd)
    if not cwd.is_dir() or not engine_root.is_dir():
        raise ValueError('sandbox_directory_missing')
    if read_only_cwd and engine_root.parent != cwd.parent:
        raise ValueError('sandbox_readonly_scope_requires_private_siblings')
    if (cwd.is_relative_to(engine_root) or engine_root.is_relative_to(cwd)
        or (input_path and safe_path(input_path).is_relative_to(cwd))):
        raise ValueError('sandbox_write_scope_overlaps_input_or_engine')
    import msvcrt
    kernel, user, adv = _api()
    system_root = windows_root()
    name = 'saw-cpu-' + uuid4().hex
    sid = c.c_void_p()
    profile = user.CreateAppContainerProfile(name, name, 'Offline bounded local model', None, 0, c.byref(sid))
    if profile:
        raise NativeError(f'APP_CONTAINER_PROFILE:{profile & 0xffffffff}')
    sidtext = w.LPWSTR()
    job = None
    pi = PROCESS_INFORMATION()
    attribute = None
    handles = []
    fds = []
    granted = []
    profile_path = w.LPWSTR()
    owner_sid = None
    owner_deny = False
    capability_allocations = []
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    first_stdout = []
    exceeded = threading.Event()
    threads = []
    started = time.monotonic()
    try:
        _check(adv.ConvertSidToStringSidW(sid, c.byref(sidtext)), 'SID_STRING')
        sidvalue = sidtext.value
        found_profile = user.GetAppContainerFolderPath(sidvalue, c.byref(profile_path))
        if found_profile or not profile_path:
            raise NativeError('APP_CONTAINER_PROFILE_PATH_FAILED')
        # Prevent untrusted code writing into its implicit AC profile outside the
        # bounded result directory. This profile was created uniquely for this run.
        _acl(Path(profile_path.value).parent, sidvalue, '(OI)(CI)(WD,AD,WEA,WA,DC,D)', recursive=True, deny=True)
        current_token = w.HANDLE()
        _check(adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, c.byref(current_token)), 'CURRENT_TOKEN')
        owner_text = w.LPWSTR()
        try:
            owner = c.create_string_buffer(1024)
            needed = w.DWORD()
            _check(adv.GetTokenInformation(current_token, 1, owner, len(owner), c.byref(needed)), 'CURRENT_USER_SID')
            _check(adv.ConvertSidToStringSidW(c.c_void_p.from_buffer(owner), c.byref(owner_text)), 'CURRENT_USER_SID_STRING')
            owner_sid = owner_text.value
            # WRITE_OWNER is needed to label an owned directory; inherited Modify
            # does not include it. This explicit grant concerns the fresh cwd only.
            if not read_only_cwd:
                _acl(cwd, owner_text.value, '(OI)(CI)F')
                _acl(cwd, 'S-1-5-18', '(OI)(CI)F')
                result = subprocess.run([str(system_root/'System32'/'icacls.exe'), str(cwd),
                                         '/inheritance:r', '/Q'], capture_output=True, check=False, timeout=30,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
                if result.returncode:
                    raise NativeError('SANDBOX_PRIVATE_OUTPUT_ACL_FAILED')
        finally:
            if owner_text:
                kernel.LocalFree(c.cast(owner_text, c.c_void_p))
            kernel.CloseHandle(current_token)
        if read_only_cwd:
            # The CPU caller seals this fresh common parent, too. Grant traversal
            # through it without adding any write right or changing its owner ACL.
            # Files have protected DACLs: an inheritable directory grant alone
            # cannot reach them. Each sealed node needs its own explicit RX ACE.
            scopes = [(path, 'RX', False) for path in
                [engine_root.parent, engine_root, cwd, *engine_root.rglob('*')]]
        else:
            scopes = [(engine_root, '(OI)(CI)RX', True), (cwd, '(OI)(CI)M', False)]
        for path, rights, recursive in scopes:
            path = safe_path(path)
            _acl(path, sidvalue, rights, recursive)
            granted.append((path, recursive))
        if input_path is not None:
            input_path = safe_path(input_path)
            _acl(input_path, sidvalue, 'R')
            granted.append((input_path, False))
        # A low integrity writable label on this fresh output directory only.
        if not read_only_cwd:
            result = subprocess.run([str(system_root/'System32'/'icacls.exe'), str(cwd),
                                     '/setintegritylevel', '(OI)(CI)L', '/Q'], capture_output=True, check=False, timeout=30,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode:
                raise NativeError('SANDBOX_OUTPUT_LABEL_FAILED')
        job = kernel.CreateJobObjectW(None, None)
        _check(job, 'CREATE_JOB')
        limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        # JOB_TIME | ACTIVE_PROCESS | PROCESS_MEMORY | JOB_MEMORY | KILL_ON_JOB_CLOSE.
        limits.BasicLimitInformation.LimitFlags = 0x4 | 0x8 | 0x100 | 0x200 | 0x2000
        limits.BasicLimitInformation.ActiveProcessLimit = 1
        limits.BasicLimitInformation.PerJobUserTimeLimit = cpu_limit
        limits.ProcessMemoryLimit = max_memory_bytes
        limits.JobMemoryLimit = max_memory_bytes
        _check(kernel.SetInformationJobObject(job, 9, c.byref(limits), c.sizeof(limits)), 'SET_JOB_LIMITS')
        observed = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        _check(kernel.QueryInformationJobObject(job, 9, c.byref(observed), c.sizeof(observed), None), 'QUERY_JOB_LIMITS')
        if (observed.BasicLimitInformation.LimitFlags != limits.BasicLimitInformation.LimitFlags
            or observed.BasicLimitInformation.ActiveProcessLimit != 1
            or not 0 < observed.BasicLimitInformation.PerJobUserTimeLimit <= limits.BasicLimitInformation.PerJobUserTimeLimit
            or observed.ProcessMemoryLimit != max_memory_bytes or observed.JobMemoryLimit != max_memory_bytes):
            raise NativeError('JOB_LIMIT_VERIFICATION_FAILED')
        readout, writeout = os.pipe()
        readerr, writeerr = os.pipe()
        null = os.open(os.devnull, os.O_RDONLY)
        fds.extend([readout, writeout, readerr, writeerr, null])
        inherited = [msvcrt.get_osfhandle(x) for x in (null, writeout, writeerr)]
        for handle in inherited:
            os.set_handle_inheritable(handle, True)
        size = c.c_size_t()
        kernel.InitializeProcThreadAttributeList(None, 4, 0, c.byref(size))
        attribute = c.create_string_buffer(size.value)
        _check(kernel.InitializeProcThreadAttributeList(attribute, 4, 0, c.byref(size)), 'INITIALIZE_ATTRIBUTES')
        # LPAC loader initialization needs read-only registry access. This single
        # documented non-network capability never grants network/COM/file rights.
        base = c.WinDLL('kernelbase', use_last_error=True)
        derive = base.DeriveCapabilitySidsFromName
        derive.argtypes = [w.LPCWSTR, c.POINTER(c.POINTER(c.c_void_p)), c.POINTER(w.DWORD),
                           c.POINTER(c.POINTER(c.c_void_p)), c.POINTER(w.DWORD)]
        derive.restype = w.BOOL
        groups, cap_sids = c.POINTER(c.c_void_p)(), c.POINTER(c.c_void_p)()
        group_count, cap_count = w.DWORD(), w.DWORD()
        _check(derive('registryRead', c.byref(groups), c.byref(group_count), c.byref(cap_sids), c.byref(cap_count)), 'DERIVE_READ_ONLY_REGISTRY_CAPABILITY')
        for array, count in [(groups, group_count), (cap_sids, cap_count)]:
            capability_allocations.extend(array[i] for i in range(count.value))
            capability_allocations.append(c.cast(array, c.c_void_p))
        if cap_count.value != 1:
            raise NativeError('READ_ONLY_CAPABILITY_COUNT_INVALID')
        caparray = (SID_AND_ATTRIBUTES*1)(SID_AND_ATTRIBUTES(cap_sids[0], 4))
        capabilities = SECURITY_CAPABILITIES(sid, c.cast(caparray, c.c_void_p), 1, 0)
        handlearray = (w.HANDLE*3)(*inherited)
        jobarray = (w.HANDLE*1)(job)
        all_packages_opt_out = w.DWORD(1)
        _check(kernel.UpdateProcThreadAttribute(attribute, 0, 0x20009, c.byref(capabilities), c.sizeof(capabilities), None, None), 'APP_CONTAINER_ATTRIBUTE')
        _check(kernel.UpdateProcThreadAttribute(attribute, 0, 0x20002, handlearray, c.sizeof(handlearray), None, None), 'HANDLE_LIST_ATTRIBUTE')
        _check(kernel.UpdateProcThreadAttribute(attribute, 0, 0x2000d, jobarray, c.sizeof(jobarray), None, None), 'ATOMIC_JOB_LIST_ATTRIBUTE')
        _check(kernel.UpdateProcThreadAttribute(attribute, 0, 0x2000f, c.byref(all_packages_opt_out), c.sizeof(all_packages_opt_out), None, None), 'LPAC_ATTRIBUTE')
        startup = STARTUPINFOEXW()
        startup.StartupInfo.cb = c.sizeof(startup)
        startup.StartupInfo.dwFlags = 0x100
        startup.StartupInfo.hStdInput, startup.StartupInfo.hStdOutput, startup.StartupInfo.hStdError = inherited
        startup.lpAttributeList = c.cast(attribute, c.c_void_p)
        env = {'SystemRoot': str(system_root), 'WINDIR': str(system_root),
               'PATH': str(engine_root), 'HOME': str(cwd), 'USERPROFILE': str(cwd), 'TMP': str(cwd), 'TEMP': str(cwd),
               'LOCALAPPDATA': str(cwd), 'APPDATA': str(cwd),
               'SOC_PCAP_PROFILE_DIRECTORY': profile_path.value,
               'WIRESHARK_CONFIG_DIR': str(cwd), 'WIRESHARK_PLUGIN_DIR': str(engine_root/'plugins')}
        block = c.create_unicode_buffer('\0'.join(f'{key}={value}' for key, value in sorted(env.items()))+'\0\0')
        command = c.create_unicode_buffer(subprocess.list2cmdline(argv))
        _check(kernel.CreateProcessW(argv[0], command, None, None, True, 0x80000|4|0x08000000|0x400,
                                     block, str(cwd), c.byref(startup), c.byref(pi)), 'CREATE_APP_CONTAINER_PROCESS')
        handles.extend([pi.hProcess, pi.hThread])
        membership = w.BOOL()
        _check(kernel.IsProcessInJob(pi.hProcess, job, c.byref(membership)), 'QUERY_ATOMIC_JOB_MEMBERSHIP')
        if not membership.value:
            raise NativeError('JOB_MEMBERSHIP_VERIFICATION_FAILED')
        # CreateProcess initializes the AC storage ACL; enforce the deny after
        # that initialization and while its first thread is still suspended.
        _acl(Path(profile_path.value).parent, sidvalue, '(OI)(CI)(WD,AD,WEA,WA,DC,D)', recursive=True, deny=True)
        # AppContainer storage has a critical package ACE. A package-only deny
        # was observed insufficient there; deny its normal user principal too,
        # solely for this fresh profile and after CreateProcess initialization.
        _acl(Path(profile_path.value).parent, owner_sid, '(OI)(CI)(WD,AD,WEA,WA)', recursive=True, deny=True)
        owner_deny = True
        token = w.HANDLE()
        _check(adv.OpenProcessToken(pi.hProcess, 8|2, c.byref(token)), 'QUERY_CHILD_TOKEN')
        try:
            needed = w.DWORD()
            iscontainer = w.DWORD()
            _check(adv.GetTokenInformation(token, 29, c.byref(iscontainer), c.sizeof(iscontainer), c.byref(needed)), 'TOKEN_APP_CONTAINER')
            package_info = c.create_string_buffer(1024)
            _check(adv.GetTokenInformation(token, 31, package_info, len(package_info), c.byref(needed)), 'TOKEN_PACKAGE_SID')
            if not adv.EqualSid(c.c_void_p.from_buffer(package_info), sid):
                raise NativeError('CHILD_PACKAGE_SID_VERIFICATION_FAILED')
            caps = c.create_string_buffer(65536)
            _check(adv.GetTokenInformation(token, 30, caps, len(caps), c.byref(needed)), 'TOKEN_CAPABILITIES')
            actual_cap = SID_AND_ATTRIBUTES.from_buffer(caps, 8 if c.sizeof(c.c_void_p) == 8 else 4)
            if (iscontainer.value != 1 or w.DWORD.from_buffer(caps).value != 1
                or not adv.EqualSid(actual_cap.Sid, cap_sids[0])):
                raise NativeError('CHILD_TOKEN_VERIFICATION_FAILED')
            _verify_lpac_access(kernel, adv, token)
            elevated = w.DWORD()
            _check(adv.GetTokenInformation(token, 20, c.byref(elevated), c.sizeof(elevated), c.byref(needed)), 'TOKEN_ELEVATION')
            label = c.create_string_buffer(1024)
            _check(adv.GetTokenInformation(token, 25, label, len(label), c.byref(needed)), 'TOKEN_INTEGRITY')
            label_sid = c.c_void_p.from_buffer(label)
            count = adv.GetSidSubAuthorityCount(label_sid)[0]
            integrity = adv.GetSidSubAuthority(label_sid, count-1)[0]
            if elevated.value != 0 or integrity > 4096:
                raise NativeError('CHILD_PRIVILEGE_VERIFICATION_FAILED')
        finally:
            kernel.CloseHandle(token)
        def drain(fd, channel):
            try:
                total = 0
                while chunk := os.read(fd, 65536):
                    if channel == 'stdout' and not first_stdout:
                        first_stdout.append(time.monotonic() - started)
                    total += len(chunk)
                    buffers[channel].extend(chunk[:max(0, max_output_bytes-len(buffers[channel]))])
                    if total > max_output_bytes:
                        exceeded.set()
            finally:
                os.close(fd)
        for fd, channel in [(readout, 'stdout'), (readerr, 'stderr')]:
            thread = threading.Thread(target=drain, args=(fd, channel), daemon=True)
            thread.start()
            threads.append(thread)
            fds.remove(fd)
        for fd in (writeout, writeerr):
            os.close(fd)
            fds.remove(fd)
        if should_cancel():
            raise NativeError('CANCELLED_BEFORE_RESUME')
        heartbeat()
        if kernel.ResumeThread(pi.hThread) == 0xffffffff:
            raise NativeError('RESUME_THREAD_FAILED')
        status = 'SUCCEEDED'
        last_heartbeat = time.monotonic()
        while kernel.WaitForSingleObject(pi.hProcess, 25) == 0x102:
            cancelled = should_cancel()
            if cancelled or exceeded.is_set() or time.monotonic()-started > max_seconds:
                status = 'CANCELLED' if cancelled else 'OUTPUT_LIMIT' if exceeded.is_set() else 'TIMEOUT'
                _check(kernel.TerminateJobObject(job, 125), 'TERMINATE_JOB')
                break
            if time.monotonic() - last_heartbeat >= 1:
                heartbeat()  # Exceptions close the Job in finally, including lease/permission loss.
                last_heartbeat = time.monotonic()
        kernel.WaitForSingleObject(pi.hProcess, 3000)
        code = w.DWORD()
        _check(kernel.GetExitCodeProcess(pi.hProcess, c.byref(code)), 'EXIT_CODE')
        for thread in threads:
            thread.join(3)
        if exceeded.is_set():
            status = 'OUTPUT_LIMIT'
        elif code.value and status == 'SUCCEEDED':
            status = 'FAILED'
        metrics = {}
        if collect_process_metrics:
            memory = PROCESS_MEMORY_COUNTERS_EX()
            memory.cb = c.sizeof(memory)
            _check(kernel.K32GetProcessMemoryInfo(pi.hProcess, c.byref(memory), c.sizeof(memory)), 'PROCESS_MEMORY')
            created, exited, kernel_time, user_time = (c.c_ulonglong() for _ in range(4))
            _check(kernel.GetProcessTimes(pi.hProcess, c.byref(created), c.byref(exited),
                c.byref(kernel_time), c.byref(user_time)), 'PROCESS_TIMES')
            peaks = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            _check(kernel.QueryInformationJobObject(job, 9, c.byref(peaks), c.sizeof(peaks), None), 'JOB_PEAK_MEMORY')
            metrics = {'peak_working_set_bytes': memory.PeakWorkingSetSize,
                'peak_private_commit_bytes': memory.PeakPagefileUsage,
                'job_peak_memory_bytes': peaks.PeakJobMemoryUsed,
                'process_cpu_seconds': (kernel_time.value + user_time.value) / 10_000_000,
                'first_stdout_seconds': first_stdout[0] if first_stdout else None}
        return {'status': status, 'returncode': code.value, 'stdout': bytes(buffers['stdout']),
                'stderr': bytes(buffers['stderr']), 'elapsed_seconds': round(time.monotonic()-started, 3),
                'token_appcontainer': True, 'token_capabilities': ['registryRead'], 'network_capability_count': 0,
                'less_privileged_appcontainer': True, 'job_active_process_limit': 1,
                'token_integrity_rid': integrity, 'token_elevated': False,
                'kernel_all_application_packages_read': False,
                'kernel_all_restricted_application_packages_read': True,
                'implicit_profile_filesystem_write_denied': True,
                'job_memory_limit_bytes': observed.ProcessMemoryLimit, 'job_kill_on_close': True,
                'job_cpu_limit_100ns': observed.BasicLimitInformation.PerJobUserTimeLimit, **metrics,
                **({'cwd_read_only': True} if read_only_cwd else {})}
    finally:
        if pi.hProcess:
            kernel.TerminateProcess(pi.hProcess, 125)
        if job:
            kernel.TerminateJobObject(job, 125)
            kernel.CloseHandle(job)
        for handle in handles:
            kernel.CloseHandle(handle)
        for fd in fds:
            os.close(fd)
        if attribute:
            kernel.DeleteProcThreadAttributeList(attribute)
        for path, recursive in reversed(granted):
            try:
                _acl(path, sidtext.value, '', recursive, remove=True)
            except NativeError:
                pass  # Stale unique SID grants cannot grant another sandbox access.
        if owner_deny:
            _acl(Path(profile_path.value).parent, owner_sid, '', recursive=True, remove_deny=True)
        if sidtext:
            kernel.LocalFree(c.cast(sidtext, c.c_void_p))
        adv.FreeSid(sid)
        if profile_path:
            ole = c.WinDLL('ole32')
            ole.CoTaskMemFree.argtypes = [c.c_void_p]
            ole.CoTaskMemFree.restype = None
            ole.CoTaskMemFree(c.cast(profile_path, c.c_void_p))
        for allocation in capability_allocations:
            kernel.LocalFree(allocation)
        deleted = user.DeleteAppContainerProfile(name)
        if deleted:
            raise NativeError(f'APP_CONTAINER_CLEANUP:{deleted & 0xffffffff}')


@contextmanager
def _lock_artifacts(paths):
    """On Windows deny write/delete sharing from hash verification through child exit."""
    handles = []
    if os.name != 'nt':
        raise NativeError('WINDOWS_SANDBOX_REQUIRED')
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    api.CreateFileW.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    try:
        for path in paths:
            handle = api.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x80, None)
            if handle == ctypes.c_void_p(-1).value:
                raise ValueError('cpu_artifact_lock_failed')
            handles.append(handle)
        yield
    finally:
        for handle in reversed(handles):
            api.CloseHandle(handle)


@contextmanager
def _lock_directories(paths):
    """Pin every directory in the search-path ancestry against rename/delete."""
    kernel, _, _ = _api()
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    handles = []
    try:
        for path in dict.fromkeys(paths):
            # BACKUP_SEMANTICS opens a directory. Share read/write, never delete.
            handle = kernel.CreateFileW(str(safe_path(path)), 0, 3, None, 3, 0x02000000, None)
            if handle == ctypes.c_void_p(-1).value:
                raise ValueError('cpu_runtime_directory_lock_failed')
            handles.append(handle)
        yield
    finally:
        for handle in reversed(handles):
            kernel.CloseHandle(handle)


@contextmanager
def _read_only_tree(paths):
    """Replace only fresh private DACLs; restore their exact descriptors on exit.

    Ordinary actor writes and LPAC writes are denied. The trusted controller
    remains the owner so it can grant the unique LPAC read access and restore
    DACLs for cleanup. This is not isolation against a compromised controller.
    """
    kernel, _, adv = _api()
    adv.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    adv.GetFileSecurityW.restype = wintypes.BOOL
    adv.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    adv.SetFileSecurityW.restype = wintypes.BOOL
    adv.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)]
    adv.GetSecurityDescriptorControl.restype = wintypes.BOOL
    token, sidtext = wintypes.HANDLE(), wintypes.LPWSTR()
    descriptor = ctypes.c_void_p()
    saved = []
    try:
        if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise NativeError('CPU_CURRENT_TOKEN')
        owner, needed = ctypes.create_string_buffer(1024), wintypes.DWORD()
        if (not adv.GetTokenInformation(token, 1, owner, len(owner), ctypes.byref(needed))
            or not adv.ConvertSidToStringSidW(ctypes.c_void_p.from_buffer(owner), ctypes.byref(sidtext))):
            raise NativeError('CPU_CURRENT_SID')
        # Protected DACL: SYSTEM full, actor read+execute. No inherited writer.
        sddl = f'D:P(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;{sidtext.value})'
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise NativeError('CPU_READ_ONLY_DESCRIPTOR')
        for path in paths:
            path = safe_path(path)
            size = wintypes.DWORD()
            adv.GetFileSecurityW(str(path), 4, None, 0, ctypes.byref(size))
            if not size.value:
                raise NativeError('CPU_SAVE_DACL_SIZE')
            original = ctypes.create_string_buffer(size.value)
            if not adv.GetFileSecurityW(str(path), 4, original, len(original), ctypes.byref(size)):
                raise NativeError('CPU_SAVE_DACL')
            control, revision = wintypes.WORD(), wintypes.DWORD()
            if not adv.GetSecurityDescriptorControl(original, ctypes.byref(control), ctypes.byref(revision)):
                raise NativeError('CPU_DACL_CONTROL')
            saved.append((path, original, bool(control.value & 0x1000)))
            if not adv.SetFileSecurityW(str(path), 4 | 0x80000000, descriptor):
                raise NativeError('CPU_SEAL_DACL')
        yield
    finally:
        restore_failed = False
        for path, original, protected in reversed(saved):
            if not adv.SetFileSecurityW(str(path), 4 | (0x80000000 if protected else 0x20000000), original):
                restore_failed = True
        if descriptor:
            kernel.LocalFree(descriptor)
        if sidtext:
            kernel.LocalFree(ctypes.cast(sidtext, ctypes.c_void_p))
        if token:
            kernel.CloseHandle(token)
        if restore_failed:
            raise NativeError('CPU_RESTORE_PRIVATE_DACL_FAILED')


@contextmanager
def _sealed_runtime(spec, work, check):
    """Execute only a hash-verified private snapshot with both discovery paths sealed."""
    work = safe_path(work)
    root = work / ('native-' + uuid4().hex)
    engine, cwd = root/'engine', root/'cwd'
    # Pinned b11429 ggml-backend-reg.cpp uses a fixed MAX_PATH buffer for
    # GetModuleFileNameW. Extended-path OS support cannot repair that runtime
    # limitation: the server must configure a shorter owned CPU work root.
    if any(len(str(path)) >= 260 for path in [cwd, *(engine/name for name in spec['runtime_files'])]):
        raise ValueError('cpu_native_path_limit_use_shorter_server_work_root')
    root.mkdir()
    try:
        engine.mkdir()
        cwd.mkdir()
        for name in spec['runtime_files']:
            check()
            target = engine/name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(_path(Path(spec['runtime_root'])/name), target)
        paths = [root, engine, cwd]
        files, dirs = [], [root, engine, cwd]
        for folder, child_dirs, names in os.walk(engine, followlinks=False):
            dirs.extend(Path(folder)/name for name in child_dirs)
            files.extend(Path(folder)/name for name in names)
        paths = list(dict.fromkeys([*paths, *dirs, *files]))
        # Holding all ancestry handles prevents replacing a search directory via
        # a writable parent; its DACL separately prevents adding unlisted files.
        with _lock_directories([*dirs, *root.parents]), _read_only_tree(paths), _lock_artifacts(files):
            actual = {p.relative_to(engine).as_posix(): p for p in engine.rglob('*') if p.is_file()}
            if set(actual) != set(spec['runtime_files']) or list(cwd.iterdir()):
                raise ValueError('cpu_runtime_snapshot_inventory')
            for name, path in actual.items():
                _verify_file(_path(path), spec['runtime_files'][name], check)
            yield engine, cwd
    finally:
        # Only this freshly-created private root can be removed. No shared
        # runtime or model ACL is changed by the snapshot lifetime.
        resolved = safe_path(root)
        if resolved.parent != work or not resolved.name.startswith('native-'):
            raise ValueError('cpu_runtime_cleanup_scope')
        shutil.rmtree(resolved)



@contextmanager
def single_execution():
    """One CPU inference across SAW processes in this Windows logon session."""
    if os.name != "nt":
        raise ValueError("cpu_windows_required")
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    api.CreateMutexW.restype = wintypes.HANDLE
    api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    api.WaitForSingleObject.restype = wintypes.DWORD
    api.ReleaseMutex.argtypes = [wintypes.HANDLE]
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = api.CreateMutexW(None, False, r"Local\SAW-Local-CPU-Inference-v1")
    if not handle:
        raise ValueError("cpu_execution_lock_failed")
    owned = False
    try:
        result = api.WaitForSingleObject(handle, 0)
        if result not in (0, 128):
            raise ValueError("cpu_single_execution_busy")
        owned = True
        yield
    finally:
        if owned:
            api.ReleaseMutex(handle)
        api.CloseHandle(handle)
