"""Synthetic service boundaries; no real registry or SCM writes."""
from contextlib import nullcontext
import importlib
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest


def desktop():
    return importlib.import_module('saw.devtools.desktop_update')


def registry(monkeypatch, root, views):
    """Model native kinds and populated-but-incomplete registry views."""
    fake = SimpleNamespace(HKEY_LOCAL_MACHINE=1, KEY_READ=0x20019,
                           KEY_WOW64_32KEY=0x200, KEY_WOW64_64KEY=0x100,
                           REG_SZ=1, REG_EXPAND_SZ=2, REG_MULTI_SZ=7)
    home = root / 'opensearch-2.19.6'
    entries = {}
    for view, change in views.items():
        options = ['-Dopensearch.path.home=' + str(home),
                   '-Dopensearch.path.conf=' + str(home / 'config')]
        data = {'': {}, 'Java': {'Jvm': (str(home / 'jdk/bin/server/jvm.dll'), 1),
                                'Options': (options, 7)},
                'Start': {'WorkingPath': (str(home), 1)}}
        if change == 'empty':
            data = {'': {}}
        elif change == 'partial':
            del data['Start']
        elif change in ('jvm_missing', 'working_missing', 'options_missing'):
            branch, field = {'jvm_missing': ('Java', 'Jvm'), 'working_missing': ('Start', 'WorkingPath'),
                             'options_missing': ('Java', 'Options')}[change]
            del data[branch][field]
        elif change == 'duplicate':
            data['Java']['Options9'] = ([options[0]], 7)
        elif change == 'conflict':
            options[0] = '-Dopensearch.path.home=' + str(root / 'foreign')
        elif change == 'config_conflict':
            options[1] = '-Dopensearch.path.conf=' + str(root / 'foreign')
        elif change == 'malformed_quote':
            options[0] = options[0].replace('=', '="', 1)
        elif change == 'interior_quote':
            options[0] += '"'
        elif change == 'wrong_options_kind':
            data['Java']['Options'] = (options, 1)
        elif change == 'wrong_jvm_kind':
            data['Java']['Jvm'] = (str(home / 'jdk/bin/server/jvm.dll'), 7)
        elif change == 'wrong_working_kind':
            data['Start']['WorkingPath'] = (str(home), 7)
        elif change == 'bad_options_value':
            data['Java']['Options'] = ('not-a-multi-string', 7)
        elif change == 'bad_option_element':
            data['Java']['Options'] = ([None], 7)
        elif change == 'quoted':
            options[:] = [key + '="' + value + '"' for key, value in
                          (item.split('=', 1) for item in options)]
        elif change == 'alternate_path':
            options[:] = [item.replace(str(home), str(home).upper().replace('\\', '/')) for item in options]
        elif change == 'override':
            data['']['Environment'] = (['PR_JVM=private-do-not-display'], 7)
        elif change not in ('valid', None):
            raise AssertionError(change)
        entries.update({(view, branch): values for branch, values in data.items()})
    prefix = r'SOFTWARE\Apache Software Foundation\ProcRun 2.0\saw-opensearch\Parameters'
    def open_key(hive, path, reserved=0, flags=0):
        assert hive == 1 and (path == prefix or path.startswith(prefix + '\\'))
        assert flags & fake.KEY_READ
        view = 32 if flags & fake.KEY_WOW64_32KEY else 64
        branch = path[len(prefix):].lstrip('\\')
        if (view, branch) not in entries:
            raise FileNotFoundError()
        return nullcontext(entries[view, branch])
    fake.OpenKey = open_key
    fake.QueryValueEx = lambda values, name: values[name] if name in values else missing()
    monkeypatch.setitem(sys.modules, 'winreg', fake)
    return fake


def missing():
    raise FileNotFoundError()


@pytest.mark.parametrize('views', [{32: 'valid'}, {64: 'valid'}, {32: 'valid', 64: 'valid'},
                                  {32: 'quoted'}, {64: 'alternate_path'}])
def test_procrun_valid_view_profiles(monkeypatch, tmp_path, views):
    registry(monkeypatch, tmp_path, views)
    desktop().WindowsController._verify_opensearch_procrun(tmp_path)


@pytest.mark.parametrize('bad', ['empty', 'partial', 'jvm_missing', 'working_missing', 'options_missing',
                                'duplicate', 'conflict', 'config_conflict', 'malformed_quote', 'interior_quote',
                                'wrong_options_kind', 'wrong_jvm_kind', 'wrong_working_kind',
                                'bad_options_value', 'bad_option_element', 'override'])
@pytest.mark.parametrize('view', [32, 64])
def test_procrun_bad_shadow_is_never_hidden(monkeypatch, tmp_path, bad, view):
    registry(monkeypatch, tmp_path, {view: bad, 96 - view: 'valid'})
    with pytest.raises(desktop().DesktopError) as error:
        desktop().WindowsController._verify_opensearch_procrun(tmp_path)
    assert error.value.code == 'service_configuration_unverified'
    assert 'private-do-not-display' not in str(error.value)


def test_procrun_missing_both_views_fails(monkeypatch, tmp_path):
    registry(monkeypatch, tmp_path, {})
    with pytest.raises(desktop().DesktopError, match='service_configuration'):
        desktop().WindowsController._verify_opensearch_procrun(tmp_path)


@pytest.mark.parametrize('name,account', [('saw', 'LocalSystem'), ('saw', r'NT AUTHORITY\SYSTEM'),
                                        ('saw-opensearch', 'localsystem'),
                                        ('saw-postgresql', r'NT AUTHORITY\NetworkService'),
                                        ('saw-postgresql', r'NT AUTHORITY\NETWORK SERVICE')])
def test_scm_account_normalization(tmp_path, name, account):
    binary = '"' + str(tmp_path / desktop().SERVICE_PATHS[name]) + '"'
    if name == 'saw-opensearch':
        binary += ' //RS//saw-opensearch'
    desktop().ServiceLease._verify_configuration(name, tmp_path, binary, 0x10, account, ['saw-postgresql', 'saw-opensearch'] if name == 'saw' else [])


@pytest.mark.parametrize('kind,account', [(0x20, 'LocalSystem'), (0x110, 'LocalSystem'),
                                         (0x10, 'LocalSystem'), (0x10, r'.\operator'), (0x10, '')])
def test_scm_rejects_wrong_postgresql_account_or_service_kind(tmp_path, kind, account):
    binary = '"' + str(tmp_path / 'service/saw-postgresql.exe') + '"'
    with pytest.raises(desktop().DesktopError, match='service_identity'):
        desktop().ServiceLease._verify_configuration('saw-postgresql', tmp_path, binary, kind, account, [])


@pytest.mark.parametrize('name', ['SAW_DATABASE_URL', 'PYTHONPATH', 'PYTHONHOME', 'JAVA_TOOL_OPTIONS',
                                  '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'PR_JVM', 'OPENSEARCH_PATH_CONF',
                                  'PGDATA'])
@pytest.mark.parametrize('source', ['machine', 'service'])
def test_execution_environment_override_refused_without_value(monkeypatch, name, source):
    fake = SimpleNamespace(HKEY_LOCAL_MACHINE=1, KEY_READ=1, REG_MULTI_SZ=7)
    fake.OpenKey = lambda hive, path, *args: nullcontext(path)
    fake.QueryInfoKey = lambda key: (0, 1 if source == 'machine' else 0, 0)
    fake.EnumValue = lambda key, i: (name, 'private-do-not-display', 1)
    fake.QueryValueEx = lambda key, field: ([name + '=private-do-not-display'], 7)
    monkeypatch.setitem(sys.modules, 'winreg', fake)
    with pytest.raises(desktop().DesktopError, match='service_environment') as error:
        desktop().WindowsController()._service_environment()
    assert 'private-do-not-display' not in str(error.value)


@pytest.mark.skipif(os.name != 'nt', reason='Windows command line parser')
def test_generated_service_configuration_accepts_https_443(tmp_path, monkeypatch):
    from xml.sax.saxutils import escape
    root = tmp_path / 'synthetic installation'
    (root / 'service').mkdir(parents=True)
    system = Path(os.environ['SystemRoot'])
    private_path = ';'.join(str(path) for path in
                            (root / 'opensearch-2.19.6/jdk/bin', system / 'System32', system))
    for source, target in [('postgresql-service.xml', 'saw-postgresql.xml'),
                           ('saw-service.xml', 'saw-service.xml')]:
        text = (Path(__file__).parents[2] / 'deploy/windows' / source).read_text(encoding='utf-8-sig')
        for key, value in {'ROOT': str(root), 'PATH': private_path, 'NAME': 'saw-postgresql',
                           'PORT': '443', 'HOST': '0.0.0.0'}.items():
            text = text.replace('{{' + key + '}}', escape(value))
        (root / 'service' / target).write_text(text, encoding='utf-8')
    registry(monkeypatch, root, {32: 'valid'})
    control = desktop().WindowsController()
    monkeypatch.setattr(control, '_service_environment', lambda: None)
    control._service_configuration(root, {'port': 443})


@pytest.mark.parametrize('transition', ['start', 'stop'])
def test_pending_service_transition_does_not_send_duplicate_control(monkeypatch, transition):
    lease = object.__new__(desktop().ServiceLease)
    lease.handle = 1
    pending, target = (2, 4) if transition == 'start' else (3, 1)
    states = iter([pending, pending, target])
    lease.status = lambda: next(states)
    def forbidden(*args):
        pytest.fail('SCM transition was interrupted by duplicate control')
    lease.api = SimpleNamespace(StartServiceW=forbidden, ControlService=forbidden)
    monkeypatch.setattr(desktop().time, 'sleep', lambda seconds: None)
    lease.change(transition == 'start')


@pytest.mark.skipif(os.name != 'nt', reason='Windows process command lines')
@pytest.mark.parametrize('change', ['none', 'orphan', 'wrong_wrapper', 'stopped', 'reused_parent', 'pid_missing', 'fork_in_pid_file'])
def test_service_postgresql_health_requires_scm_linked_live_processes(tmp_path, monkeypatch, change):
    root = tmp_path / 'install'
    (root / 'data/postgresql').mkdir(parents=True)
    (root / 'data/postgresql/postmaster.pid').write_text('200\n', encoding='ascii')
    ctl = desktop().WindowsController()
    services = {'saw': (100, 'saw'), 'saw-postgresql': (101, 'postgresql'),
                'saw-opensearch': (102, 'opensearch')}
    records = []
    for name, (pid, group) in services.items():
        image = str(root / desktop().SERVICE_PATHS[name])
        command = subprocess.list2cmdline([image] + (['//RS//saw-opensearch'] if group == 'opensearch' else []))
        records.append(dict(ProcessId=pid, ParentProcessId=1, ExecutablePath=image, CommandLine=command))
        ctl.services[name] = SimpleNamespace(process_id=lambda pid=pid: pid,
                                             status=lambda: 1 if change == 'stopped' else 4)
    pg = str(root / 'pgsql/bin/postgres.exe')
    records.append(dict(ProcessId=200, ParentProcessId=999 if change == 'orphan' else 101,
                        ExecutablePath=pg,
                        CommandLine=subprocess.list2cmdline([pg, '-D', str(root / 'data/postgresql')])))
    if change == 'fork_in_pid_file':
        records[-1]['CommandLine'] = subprocess.list2cmdline([pg, '--forkbackend', '1234'])
    if change == 'wrong_wrapper':
        records[1]['ExecutablePath'] = str(root / 'foreign.exe')
    if change == 'pid_missing':
        records.pop()
    class Lease:
        def __init__(self, pid, image, *, terminate=True):
            assert terminate is False
            self.created_at = 300 if change == 'reused_parent' and pid == 101 else pid
            self.handle = pid
            self.kernel = SimpleNamespace(WaitForSingleObject=lambda *args: 258)
        def close(self):
            pass
    monkeypatch.setattr(desktop(), 'ProcessLease', Lease)
    monkeypatch.setattr(ctl, '_processes', lambda: records)
    monkeypatch.setattr(ctl, '_pg', lambda *args: pytest.fail('service health used cross-account pg_ctl status'))
    monkeypatch.setattr(ctl, '_pg_ready', lambda *args: True)
    checks = []
    monkeypatch.setattr(desktop().health, 'check', lambda *args: checks.append(args) or True)
    assert ctl.healthy(root, {'port': 443, 'postgresPort': 5432, 'opensearchPort': 9200}, 'localhost') is (change == 'none')
    assert ('api', 443, root / 'tls/saw.crt', 'localhost') in checks


@pytest.mark.skipif(os.name != 'nt', reason='Windows process command lines')
@pytest.mark.parametrize('change', ['none', 'orphan', 'changed_parent', 'reused_parent', 'missing_parent'])
def test_postgresql_fork_child_needs_retained_verified_parent(tmp_path, monkeypatch, change):
    root = tmp_path / 'install'
    image = str(root / 'pgsql/bin/postgres.exe')
    main = dict(ProcessId=200, ParentProcessId=1, ExecutablePath=image,
                CommandLine=subprocess.list2cmdline([image, '-D', str(root / 'data/postgresql')]))
    child = dict(ProcessId=201, ParentProcessId=999 if change == 'orphan' else 200, ExecutablePath=image,
                 CommandLine=subprocess.list2cmdline([image, '--forkbackend', '1234']))
    count = [0]
    def processes():
        count[0] += 1
        row = dict(child)
        if change == 'changed_parent' and count[0] > 1:
            row['ParentProcessId'] = 999
        return [dict(main), row]
    class Lease:
        def __init__(self, pid, image):
            if change == 'missing_parent' and pid == 200:
                raise desktop().DesktopError('process_missing')
            self.created_at = 300 if change == 'reused_parent' and pid == 200 else pid
        def close(self):
            pass
    ctl = desktop().WindowsController()
    monkeypatch.setattr(ctl, '_processes', processes)
    monkeypatch.setattr(desktop(), 'ProcessLease', Lease)
    if change == 'none':
        with ctl.claim(root, {}, 'noadmin'):
            assert len(ctl.leases) == 2
    else:
        with pytest.raises(desktop().DesktopError, match='process_identity'):
            with ctl.claim(root, {}, 'noadmin'):
                pytest.fail('PostgreSQL child accepted without its original verified parent')


@pytest.mark.parametrize('name,dependencies', [
    ('saw', ['foreign-service']), ('saw-postgresql', ['foreign-service']),
    ('saw-opensearch', ['foreign-service']), ('saw', ['saw-postgresql']),
    ('saw-opensearch', ['Tcpip', 'Tcpip']),
])
def test_scm_unverified_dependencies_are_refused_before_service_control(tmp_path, name, dependencies):
    binary = '"' + str(tmp_path / desktop().SERVICE_PATHS[name]) + '"'
    if name == 'saw-opensearch':
        binary += ' //RS//saw-opensearch'
    account = r'NT AUTHORITY\NetworkService' if name == 'saw-postgresql' else 'LocalSystem'
    with pytest.raises(desktop().DesktopError, match='service_identity'):
        desktop().ServiceLease._verify_configuration(name, tmp_path, binary, 0x10, account, dependencies)


@pytest.mark.skipif(os.name != 'nt', reason='Windows SCM native structure layout')
@pytest.mark.parametrize('change', ['none', 'single_empty', 'wrong_account', 'foreign_dependency', 'bad_pointer'])
def test_service_lease_reads_native_configuration_and_pid_without_mutating_scm(tmp_path, monkeypatch, change):
    import ctypes
    from ctypes import wintypes as w
    class Config(ctypes.Structure):
        _fields_ = [('kind', w.DWORD), ('start', w.DWORD), ('error', w.DWORD),
                    ('binary', w.LPWSTR), ('group', w.LPWSTR), ('tag', w.DWORD),
                    ('dependencies', ctypes.c_void_p), ('account', w.LPWSTR), ('display', w.LPWSTR)]
    dependency = (ctypes.create_unicode_buffer('', 1) if change == 'single_empty' else
                  ctypes.create_unicode_buffer('foreign\0\0' if change == 'foreign_dependency' else '\0\0'))
    retained, closed = [], []
    def query(handle, buffer, size, needed):
        total = ctypes.sizeof(Config) + ctypes.sizeof(dependency)
        ctypes.cast(needed, ctypes.POINTER(w.DWORD))[0] = total
        if buffer is None:
            return False
        config = Config()
        config.kind, config.start = 0x10, 2
        config.binary = '"' + str(tmp_path / 'service/saw-postgresql.exe') + '"'
        config.account = 'LocalSystem' if change == 'wrong_account' else r'NT AUTHORITY\NetworkService'
        config.dependencies = ctypes.addressof(buffer) + (total + 4 if change == 'bad_pointer' else ctypes.sizeof(Config))
        retained.append(config)
        ctypes.memmove(buffer, ctypes.byref(config), ctypes.sizeof(Config))
        ctypes.memmove(ctypes.addressof(buffer) + ctypes.sizeof(Config), dependency, ctypes.sizeof(dependency))
        return True
    def status(handle, level, values, size, needed):
        values[1], values[7] = 4, 1234
        return True
    def manager(*args):
        return 1
    def service(*args):
        return 2
    def close(handle):
        closed.append(handle)
    def forbidden(*args):
        pytest.fail('Read-only service identity verification tried to mutate SCM')
    api = SimpleNamespace(OpenSCManagerW=manager, OpenServiceW=service, CloseServiceHandle=close,
                          QueryServiceConfigW=query, QueryServiceStatusEx=status,
                          ControlService=forbidden, StartServiceW=forbidden)
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *args, **kwargs: api)
    if change in ('none', 'single_empty'):
        lease = desktop().ServiceLease('saw-postgresql', tmp_path)
        try:
            assert lease.status() == 4 and lease.process_id() == 1234
        finally:
            lease.close()
    else:
        with pytest.raises(desktop().DesktopError, match='service_identity'):
            desktop().ServiceLease('saw-postgresql', tmp_path)
    assert closed == [1, 2]
