"""Desktop orchestration preserves cold-update boundaries and reports honest state."""
from __future__ import annotations

from contextlib import contextmanager
import importlib
import json
from pathlib import Path

import pytest
_spec = importlib.util.spec_from_file_location('_desktop_cold_fixture', Path(__file__).with_name('test_offline_update.py'))
_fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixture)
installation, updater, write = _fixture.installation, _fixture.updater, _fixture.write


def desktop():
    try:
        return importlib.import_module('saw.devtools.desktop_update')
    except ModuleNotFoundError:
        pytest.fail('The desktop update orchestrator is missing')


class ControlledLifecycle:
    """Replace only real service/process operations, never the update engine."""
    def __init__(self, fail=None):
        self.fail = fail
        self.events = []

    def identity(self):
        return {'admin': False, 'services': []}

    @contextmanager
    def claim(self, root, cfg, mode):
        if self.fail == 'ownership':
            raise desktop().DesktopError('ownership_unverified')
        yield self

    def stop(self, root, cfg, mode):
        self.events.append('stop')
        if self.fail == 'stop':
            raise desktop().DesktopError('stop_failed')

    def start(self, root, cfg, mode):
        self.events.append('start')
        if self.fail == 'start':
            raise desktop().DesktopError('start_failed')

    def healthy(self, root, cfg, host):
        self.events.append('health')
        return self.fail != 'health'


@pytest.fixture
def desktop_installation(installation):
    root, bundle, baseline, recovery = installation
    write(root, '.saw-install-state.json', json.dumps({
        'schema': 'saw.install-state/1', 'root': str(root), 'status': 'complete',
        'options': {'noAdmin': True, 'noServices': False, 'hostName': 'localhost'},
    }))
    state = root.parent / 'worker-state'
    updater()._private_directory(state)
    return root, bundle, baseline, recovery, state


def run_case(parts, action='inspect', control=None, **kwargs):
    root, bundle, baseline, recovery, state = parts
    return desktop().run(action, root, bundle, state, baseline_dir=baseline,
                         recovery_point=recovery if action in ('apply', 'restore') else None,
                         controller=control or ControlledLifecycle(), **kwargs)


def test_inspect_reports_ready_without_stopping_or_copying(desktop_installation):
    control = ControlledLifecycle()
    result = run_case(desktop_installation, control=control)
    root, _, _, recovery, state = desktop_installation
    assert result['status'] == 'ready'
    assert result['mode'] == 'noadmin'
    assert result['app_url'] == 'https://localhost:58101/'
    assert not recovery.exists()
    assert control.events == []
    assert json.loads((state / 'state.json').read_text()) == result
    assert (root / 'app/saw/main.py').read_text() == 'old app'


@pytest.mark.parametrize('action,kwargs,code', [
    ('apply', {}, 'maintenance_confirmation_required'),
    ('restore', {'maintenance_confirmed': True}, 'recovery_confirmation_required'),
])
def test_unacknowledged_mutation_never_stops(desktop_installation, action, kwargs, code):
    control = ControlledLifecycle()
    result = run_case(desktop_installation, action, control, **kwargs)
    assert result['status'] == 'failed'
    assert result['code'] == code
    assert control.events == []
    assert not desktop_installation[3].exists()


def test_apply_and_restore_use_real_backend_and_preserve_private_state(desktop_installation):
    root, _, _, recovery, _ = desktop_installation
    secret = (root / 'app/var/secret.key').read_bytes()
    control = ControlledLifecycle()
    result = run_case(desktop_installation, 'apply', control, maintenance_confirmed=True)
    assert result['status'] == 'completed'
    assert result['needs_acceptance'] is True
    assert (root / 'app/saw/main.py').read_text() == 'new app'
    assert (root / 'app/var/secret.key').read_bytes() == secret
    assert (recovery / 'recovery-point.json').is_file()
    assert control.events == ['stop', 'start', 'health']
    write(root, 'data/objects/new-record', 'synthetic newer evidence')
    # The installed manifest is now authoritative, not the old override.
    result = desktop().run('restore', root, desktop_installation[1], desktop_installation[4],
                           recovery_point=recovery, maintenance_confirmed=True, confirm=True,
                           controller=ControlledLifecycle())
    assert result['status'] == 'completed'
    assert (root / 'app/saw/main.py').read_text() == 'old app'
    assert (Path(result['retained_installation']) / 'data/objects/new-record').is_file()


@pytest.mark.parametrize('failure', ['ownership', 'stop', 'start', 'health'])
def test_lifecycle_failures_never_report_success_or_retry(desktop_installation, failure):
    control = ControlledLifecycle(failure)
    result = run_case(desktop_installation, 'apply', control, maintenance_confirmed=True)
    root, _, _, recovery, _ = desktop_installation
    assert result['status'] == 'failed'
    assert control.events.count('start') <= 1
    if failure in ('ownership', 'stop'):
        assert 'start' not in control.events
        assert (root / 'app/saw/main.py').read_text() == 'old app'
    else:
        assert (recovery / 'recovery-point.json').is_file()
        assert (root / 'app/saw/main.py').read_text() == 'new app'


@pytest.mark.parametrize('relative', ['app/saw/main.py', 'pgsql/bin/postgres.exe'])
def test_changed_installed_code_is_refused_before_stop(desktop_installation, relative):
    root = desktop_installation[0]
    write(root, relative, 'unverified local change')
    control = ControlledLifecycle()
    result = run_case(desktop_installation, 'apply', control, maintenance_confirmed=True)
    assert result['status'] == 'failed'
    assert control.events == []
    assert not desktop_installation[3].exists()


def test_backend_failure_keeps_snapshot_and_does_not_restart(desktop_installation, monkeypatch):
    root, _, _, recovery, state = desktop_installation
    original = updater()._stage_public_app
    def failure(*args):
        original(*args)
        raise OSError('secret-password-do-not-disclose')
    monkeypatch.setattr(updater(), '_stage_public_app', failure)
    control = ControlledLifecycle()
    result = run_case(desktop_installation, 'apply', control, maintenance_confirmed=True)
    assert result['status'] == 'failed'
    assert (recovery / 'recovery-point.json').is_file()
    assert 'start' not in control.events
    assert 'secret-password' not in (state / 'state.json').read_text()
    assert (root / 'app/saw/main.py').read_text() == 'old app'


def test_existing_backend_lock_blocks_gui_before_stop(desktop_installation):
    control = ControlledLifecycle()
    with updater()._maintenance(desktop_installation[0]):
        result = run_case(desktop_installation, 'apply', control, maintenance_confirmed=True)
    assert result['status'] == 'failed'
    assert control.events == []
    assert not desktop_installation[3].exists()


@pytest.mark.parametrize('location', ['installation', 'media', 'recovery'])
def test_nested_status_path_is_never_written(desktop_installation, location):
    root, bundle, baseline, recovery, _ = desktop_installation
    target = {'installation': root, 'media': bundle, 'recovery': recovery}[location] / 'state'
    target.mkdir(parents=True)
    with pytest.raises(desktop().DesktopError):
        desktop().run('inspect', root, bundle, target, baseline_dir=baseline,
                      recovery_point=recovery, controller=ControlledLifecycle())
    assert not (target / 'state.json').exists()


@pytest.mark.parametrize('change', ['root', 'unfinished', 'no_services'])
def test_ambiguous_or_incomplete_installation_refuses_control(desktop_installation, change):
    root = desktop_installation[0]
    path = root / '.saw-install-state.json'
    value = json.loads(path.read_text())
    if change == 'root': value['root'] = str(root.parent / 'another-installation')
    elif change == 'unfinished': value['status'] = 'running'
    else: value['options']['noServices'] = True
    path.write_text(json.dumps(value))
    control = ControlledLifecycle()
    result = run_case(desktop_installation, 'apply', control, maintenance_confirmed=True)
    assert result['status'] == 'failed'
    assert control.events == []


def test_worker_claims_same_lock_during_stop_and_start(desktop_installation):
    class LockProbe(ControlledLifecycle):
        def stop(self, root, cfg, mode):
            with pytest.raises(updater().UpdateError):
                with updater()._maintenance(root): pass
            super().stop(root, cfg, mode)
        def start(self, root, cfg, mode):
            with pytest.raises(updater().UpdateError):
                with updater()._maintenance(root): pass
            super().start(root, cfg, mode)
    result = run_case(desktop_installation, 'apply', LockProbe(), maintenance_confirmed=True)
    assert result['status'] == 'completed'


def test_foreign_service_is_not_inferred_as_this_installation(tmp_path):
    root = tmp_path / 'install'
    root.mkdir()
    write(root, '.saw-install-state.json', json.dumps({'schema': 'saw.install-state/1',
        'root': str(root), 'status': 'complete', 'options': {'noAdmin': False, 'noServices': False}}))
    services = [
        {'Name': 'saw', 'PathName': str(tmp_path / 'other/service/saw-service.exe')},
        {'Name': 'saw-postgresql', 'PathName': str(root / 'service/saw-postgresql.exe')},
        {'Name': 'saw-opensearch', 'PathName': str(root / 'opensearch-2.19.6/bin/opensearch-service-x64.exe') + ' //RS//saw-opensearch'},
    ]
    with pytest.raises(desktop().DesktopError, match='foreign_service'):
        desktop()._mode(root, {'admin': True, 'services': services})


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows process handles')
def test_native_process_handle_refuses_foreign_image_without_killing_it():
    import subprocess
    import sys
    process = subprocess.Popen([sys.executable, '-B', '-c', 'import time; time.sleep(60)'])
    try:
        with pytest.raises(desktop().DesktopError, match='process_identity'):
            desktop().ProcessLease(process.pid, Path(sys.executable).with_name('foreign.exe'))
        assert process.poll() is None
    finally:
        process.terminate()
        process.wait(timeout=10)


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows process handles')
def test_native_termination_targets_retained_process_handle():
    import subprocess
    import sys
    process = subprocess.Popen([sys.executable, '-B', '-c', 'import time; time.sleep(60)'])
    lease = None
    try:
        lease = desktop().ProcessLease(process.pid, Path(sys.executable))
        lease.stop()
        process.wait(timeout=10)
        assert process.returncode != 0
    finally:
        if lease is not None:
            lease.close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)


def test_foreign_tracked_pid_is_rejected_before_any_termination(tmp_path, monkeypatch):
    root = tmp_path / 'install'
    root.mkdir()
    write(root, 'run/saw.pid', '1234')
    records = [{'ProcessId': 1234, 'ParentProcessId': 1, 'ExecutablePath': 'C:\\Windows\\System32\\notepad.exe',
                'CommandLine': 'notepad.exe'}]
    control = desktop().WindowsController()
    monkeypatch.setattr(control, '_processes', lambda: records)
    with pytest.raises(desktop().DesktopError, match='process_identity'):
        with control.claim(root, {}, 'noadmin'):
            pytest.fail('Foreign tracked PID was accepted')


def test_service_config_points_to_different_data_is_refused(tmp_path):
    root = tmp_path / 'install'
    root.mkdir()
    write(root, 'service/saw-postgresql.xml', '<service><id>saw-postgresql</id><executable>C:\\other\\postgres.exe</executable></service>')
    with pytest.raises(desktop().DesktopError, match='service_configuration'):
        desktop().WindowsController()._service_configuration(root, {'port': 58101})


def test_partial_application_switch_can_restore_verified_snapshot(desktop_installation):
    root, bundle, baseline, recovery, state = desktop_installation
    updater().apply(root, bundle, recovery, baseline)
    # A failed post-switch manifest write can leave mismatched application identity.
    write(root, 'app/saw/main.py', 'interrupted application switch')
    result = desktop().run('restore', root, bundle, state, recovery_point=recovery,
                           maintenance_confirmed=True, confirm=True, controller=ControlledLifecycle())
    assert result['status'] == 'completed'
    assert (root / 'app/saw/main.py').read_text() == 'old app'
    assert (Path(result['retained_installation']) / 'app/saw/main.py').read_text() == 'interrupted application switch'


def test_corrupt_snapshot_is_refused_before_stopping(desktop_installation):
    root, bundle, baseline, recovery, state = desktop_installation
    updater().apply(root, bundle, recovery, baseline)
    write(recovery, 'installation/data/objects/evidence', 'corrupt synthetic snapshot')
    control = ControlledLifecycle()
    result = desktop().run('restore', root, bundle, state, recovery_point=recovery,
                           maintenance_confirmed=True, confirm=True, controller=control)
    assert result['status'] == 'failed'
    assert control.events == []
    assert (root / 'app/saw/main.py').read_text() == 'new app'


def test_postgresql_process_with_other_data_directory_is_not_owned(tmp_path):
    root = tmp_path / 'install'
    control = desktop().WindowsController()
    command = '"' + str(root / 'pgsql/bin/postgres.exe') + '" -D "' + str(tmp_path / 'other-data') + '"'
    assert control._classify(root, str(root / 'pgsql/bin/postgres.exe'), command) is None


def test_service_inspection_can_request_elevation_before_private_file_reads(desktop_installation, monkeypatch):
    root = desktop_installation[0]
    class ServiceControl(ControlledLifecycle):
        def identity(self):
            return {'admin': False, 'services': [
                {'Name': name, 'PathName': str(root / path) + (' //RS//saw-opensearch' if name == 'saw-opensearch' else '')}
                for name, path in desktop().SERVICE_PATHS.items()]}
    def denied(*args):
        raise PermissionError('private installation unavailable to unelevated token')
    monkeypatch.setattr(desktop(), '_static_access', denied)
    result = run_case(desktop_installation, control=ServiceControl())
    assert result['status'] == 'ready'
    assert result['requires_admin'] is True
    assert result['code'] == 'administrator_required'


def test_unsafe_log_hardlink_is_refused_before_child_launch(tmp_path):
    import os
    root = tmp_path / 'install'
    target = tmp_path / 'outside.txt'
    target.write_text('preserve synthetic outside data')
    path = root / 'logs/saw/desktop-console.log'
    path.parent.mkdir(parents=True)
    os.link(target, path)
    with pytest.raises(desktop().DesktopError):
        desktop().WindowsController()._launch(root, ['must-not-execute'], root, 'saw/desktop-console.log', 'saw')
    assert target.read_text() == 'preserve synthetic outside data'


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows process handles')
@pytest.mark.parametrize('changed', [False, True])
def test_only_unchanged_tracking_record_for_terminated_owned_process_is_removed(tmp_path, changed):
    import subprocess
    import sys
    root = tmp_path / 'install'
    root.mkdir()
    process = subprocess.Popen([sys.executable, '-B', '-c', 'import time; time.sleep(60)'])
    lease = desktop().ProcessLease(process.pid, Path(sys.executable))
    control = desktop().WindowsController()
    control.leases = [(process.pid, 0, 'saw', lease)]
    control.tracking['saw'] = str(process.pid).encode('ascii')
    path = root / 'run/saw.pid'
    write(root, 'run/saw.pid', str(process.pid + 1 if changed else process.pid))
    try:
        lease.stop()
        if changed:
            with pytest.raises(desktop().DesktopError, match='tracking_changed'):
                control._forget_tracked(root, 'saw')
            assert path.read_text() == str(process.pid + 1)
        else:
            control._forget_tracked(root, 'saw')
            assert not path.exists()
    finally:
        lease.close()
        process.wait(timeout=10)


def test_health_does_not_accept_postgres_process_without_readiness(tmp_path, monkeypatch):
    from types import SimpleNamespace
    control = desktop().WindowsController()
    monkeypatch.setattr(desktop().health, 'check', lambda *args: True)
    def native(args, **kwargs):
        return SimpleNamespace(returncode=1 if Path(args[0]).name == 'pg_isready.exe' else 0)
    monkeypatch.setattr(desktop().subprocess, 'run', native)
    cfg = {'port': 58101, 'postgresPort': 58102, 'opensearchPort': 58103}
    assert control.healthy(tmp_path, cfg, 'localhost') is False


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows state ACL')
def test_public_status_directory_is_refused_before_any_status_write(desktop_installation):
    root, bundle, baseline, _, state = desktop_installation
    sid = desktop()._current_sid()
    updater()._set_acl(state, 'D:P(A;OICI;FA;;;' + sid + ')(A;OICI;FR;;;BU)')
    with pytest.raises(desktop().DesktopError):
        desktop().run('inspect', root, bundle, state, baseline_dir=baseline, controller=ControlledLifecycle())
    assert not (state / 'state.json').exists()


def test_apply_reserves_additional_whole_restore_headroom(desktop_installation, monkeypatch):
    from types import SimpleNamespace
    root, bundle, baseline, recovery, _ = desktop_installation
    plan = updater().plan(root, bundle, baseline)
    available = plan['required_free_bytes'] + plan['snapshot_bytes']
    monkeypatch.setattr(updater().shutil, 'disk_usage', lambda path: SimpleNamespace(free=available))
    control = ControlledLifecycle()
    result = run_case(desktop_installation, 'apply', control, maintenance_confirmed=True)
    assert result['status'] == 'failed'
    assert result['code'] == 'recovery_headroom_insufficient'
    assert not recovery.exists()
    assert 'start' not in control.events
    assert (root / 'app/saw/main.py').read_text() == 'old app'


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows stale PID')
def test_proven_absent_stale_pid_record_can_be_retired(tmp_path):
    import subprocess
    import sys
    child = subprocess.run([sys.executable, '-B', '-c', 'import os; print(os.getpid())'],
                           capture_output=True, text=True, check=True)
    pid = int(child.stdout.strip())
    root = tmp_path / 'install'
    root.mkdir()
    write(root, 'run/saw.pid', str(pid))
    control = desktop().WindowsController()
    with control.claim(root, {}, 'noadmin'):
        control._forget_tracked(root, 'saw')
    assert not (root / 'run/saw.pid').exists()


def test_desktop_restore_recovers_missing_application_directory(desktop_installation):
    root, bundle, baseline, recovery, state = desktop_installation
    updater().apply(root, bundle, recovery, baseline)
    (root / 'app').rename(root.parent / 'stranded-app')
    result = desktop().run('restore', root, bundle, state, recovery_point=recovery,
                           maintenance_confirmed=True, confirm=True, controller=ControlledLifecycle())
    assert result['status'] == 'completed'
    assert (root / 'app/saw/main.py').read_text() == 'old app'


@pytest.mark.parametrize('extra', [
    '<env name="SAW_DATABASE_URL" value="private-do-not-display"/>',
    '<prestart><executable>foreign.exe</executable></prestart>',
    '<env name="PYTHONUTF8" value="1"/>',
])
def test_service_xml_rejects_environment_overrides_and_execution_hooks(tmp_path, extra):
    import xml.etree.ElementTree as ET
    xml = ET.fromstring('<service><env name="PYTHONUTF8" value="1"/>' + extra + '</service>')
    with pytest.raises(desktop().DesktopError, match='service_configuration'):
        desktop().WindowsController()._xml_policy(xml, 'app', tmp_path)


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows stale PID')
def test_changed_tracking_bytes_are_preserved_even_for_same_absent_pid(tmp_path):
    import subprocess
    import sys
    child = subprocess.run([sys.executable, '-B', '-c', 'import os; print(os.getpid())'],
                           capture_output=True, text=True, check=True)
    pid = int(child.stdout.strip())
    root = tmp_path / 'install'
    root.mkdir()
    write(root, 'run/saw.pid', str(pid))
    control = desktop().WindowsController()
    with control.claim(root, {}, 'noadmin'):
        write(root, 'run/saw.pid', str(pid) + '\n')
        with pytest.raises(desktop().DesktopError, match='tracking_changed'):
            control._forget_tracked(root, 'saw')
    assert (root / 'run/saw.pid').read_bytes() == (str(pid) + '\n').encode('ascii')


@pytest.mark.parametrize('kind,filename', [('app', 'saw-service.xml'), ('pg', 'postgresql-service.xml')])
def test_current_installer_service_templates_are_accepted(tmp_path, kind, filename):
    import os
    import xml.etree.ElementTree as ET
    from xml.sax.saxutils import escape
    root = tmp_path / 'synthetic install'
    system = Path(os.environ.get('SystemRoot', 'C:/Windows'))
    private_path = str(root / 'opensearch-2.19.6/jdk/bin') + ';' + str(system / 'System32') + ';' + str(system)
    text = (Path(__file__).parents[2] / 'deploy/windows' / filename).read_text(encoding='utf-8-sig')
    text = text.replace('{{ROOT}}', escape(str(root))).replace('{{PATH}}', escape(private_path))
    desktop().WindowsController()._xml_policy(ET.fromstring(text), kind, root)


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows service environment')
@pytest.mark.parametrize('source', ['machine', 'service'])
def test_service_environment_overrides_are_refused_without_exposing_values(monkeypatch, source):
    import winreg
    from contextlib import nullcontext
    monkeypatch.setattr(winreg, 'OpenKey', lambda hive, path, *args: nullcontext(path))
    monkeypatch.setattr(winreg, 'QueryInfoKey', lambda key: (0, 1 if source == 'machine' else 0, 0))
    monkeypatch.setattr(winreg, 'EnumValue', lambda key, index: ('SAW_DATABASE_URL', 'private-do-not-display', winreg.REG_SZ))
    monkeypatch.setattr(winreg, 'QueryValueEx', lambda key, name: (['SAW_DATABASE_URL=private-do-not-display'], winreg.REG_MULTI_SZ))
    with pytest.raises(desktop().DesktopError, match='service_environment_unverified') as error:
        desktop().WindowsController()._service_environment()
    assert 'private-do-not-display' not in str(error.value)


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows native log paths')
@pytest.mark.parametrize('link_kind', ['hardlink', 'junction'])
def test_postgresql_unsafe_log_target_is_refused_before_start(tmp_path, monkeypatch, link_kind):
    import os
    import subprocess
    root = tmp_path / 'install'
    root.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    target = outside / 'postgresql.log'
    target.write_text('preserve outside synthetic log')
    log_directory = root / 'logs/postgresql'
    log_directory.parent.mkdir(parents=True)
    if link_kind == 'hardlink':
        log_directory.mkdir()
        os.link(target, log_directory / 'postgresql.log')
    else:
        result = subprocess.run([os.environ['COMSPEC'], '/d', '/c', 'mklink', '/J',
                                 str(log_directory), str(outside)], capture_output=True)
        assert result.returncode == 0
    control = desktop().WindowsController()
    calls = []
    def forbidden(*args, **kwargs):
        calls.append('pg_start')
        raise AssertionError('PostgreSQL was invoked before log verification')
    monkeypatch.setattr(control, '_pg', forbidden)
    try:
        with pytest.raises((desktop().DesktopError, desktop().backend.UpdateError)):
            control.start(root, {'opensearchPort': 58103}, 'noadmin')
        assert calls == []
        assert target.read_text() == 'preserve outside synthetic log'
    finally:
        if link_kind == 'junction':
            log_directory.rmdir()


def test_private_startup_log_directory_is_accepted(tmp_path):
    root = tmp_path / 'private-install'
    updater()._private_directory(root)
    control = desktop().WindowsController()
    log = control._log_path(root, 'postgresql/postgresql.log')
    assert log == root / 'logs/postgresql/postgresql.log'
    assert log.parent.is_dir()
    assert not log.exists()


def test_installed_manifest_supersedes_old_baseline_for_inspect_start_and_apply(desktop_installation, monkeypatch):
    import functools
    root, bundle, baseline, recovery, state = desktop_installation
    updater().apply(root, bundle, recovery, baseline)
    for action in ('inspect', 'start'):
        result = desktop().run(action, root, bundle, state, baseline_dir=baseline,
                               controller=ControlledLifecycle())
        assert result['status'] == ('ready' if action == 'inspect' else 'completed')
    seen = []
    original_plan = updater().plan
    def plan(install_root, new_bundle, baseline_override):
        seen.append(('plan', baseline_override))
        return original_plan(install_root, new_bundle, baseline_override)
    def apply(install_root, new_bundle, point, baseline_override):
        seen.append(('apply', baseline_override))
        raise OSError('synthetic stop after validated plan')
    @functools.wraps(apply)
    def wrapped(*args, **kwargs):
        raise AssertionError('The existing lock must remain held')
    monkeypatch.setattr(updater(), 'plan', plan)
    monkeypatch.setattr(updater(), 'apply', wrapped)
    fresh_recovery = root.parent / 'another-recovery'
    result = desktop().run('apply', root, bundle, state, baseline_dir=baseline,
                           recovery_point=fresh_recovery, maintenance_confirmed=True,
                           controller=ControlledLifecycle())
    assert result['status'] == 'failed'
    assert seen == [('plan', None), ('apply', None)]
    assert not fresh_recovery.exists()


def test_corrupt_installed_manifest_never_falls_back_to_old_media(desktop_installation):
    root, _, _, _, _ = desktop_installation
    write(root, 'installed-release-manifest.json', '{broken synthetic manifest')
    control = ControlledLifecycle()
    result = run_case(desktop_installation, control=control)
    assert result['status'] == 'failed'
    assert control.events == []


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows command lines')
@pytest.mark.parametrize('engine', ['postgresql', 'opensearch'])
@pytest.mark.parametrize('form', ['forward', 'case', 'other', 'duplicate', 'attached_duplicate'])
def test_native_engine_argument_paths_use_single_windows_equivalent_path(tmp_path, engine, form):
    import subprocess
    root = tmp_path / 'synthetic installed 한글'
    if engine == 'postgresql':
        image = root / 'pgsql/bin/postgres.exe'
        path = root / 'data/postgresql'
    else:
        image = root / 'opensearch-2.19.6/jdk/bin/java.exe'
        path = root / 'opensearch-2.19.6'
    value = path.as_posix() if form == 'forward' else str(path).upper() if form == 'case' else str(path)
    if form == 'other':
        value = str(path.with_name(path.name + '-other'))
    options = ['-D', value] if engine == 'postgresql' else ['-Dopensearch.path.home=' + value]
    if form == 'duplicate':
        options += ['-D', str(path.parent / 'foreign')] if engine == 'postgresql' else ['-Dopensearch.path.home=' + str(path.parent / 'foreign')]
    if form == 'attached_duplicate':
        options += ['-D' + str(path.parent / 'foreign')] if engine == 'postgresql' else ['-Dopensearch.path.home=' + str(path.parent / 'foreign')]
    command = subprocess.list2cmdline([str(image), *options])
    result = desktop().WindowsController()._classify(root, str(image), command)
    assert result == (engine if form in ('forward', 'case') else None)


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows console ownership')
@pytest.mark.parametrize('change', ['none', 'foreign_image', 'extra_argument', 'changed_parent', 'reused_parent', 'missing_parent'])
def test_native_console_descendant_requires_retained_matching_parent(tmp_path, monkeypatch, change):
    import os
    import subprocess
    from types import SimpleNamespace
    root = tmp_path / 'install'
    root.mkdir()
    image = root / 'opensearch-2.19.6/jdk/bin/java.exe'
    system = Path(os.environ['SystemRoot']) / 'System32/conhost.exe'
    parent = {'ProcessId': 1234, 'ParentProcessId': 9, 'ExecutablePath': str(image),
              'CommandLine': subprocess.list2cmdline([str(image), '-Dopensearch.path.home=' + str(root / 'opensearch-2.19.6')])}
    child = {'ProcessId': 4321, 'ParentProcessId': 1234, 'ExecutablePath': str(system),
             'CommandLine': subprocess.list2cmdline(['\\??\\' + str(system), '0x4'])}
    if change == 'foreign_image':
        child['ExecutablePath'] = str(root / 'foreign/conhost.exe')
    if change == 'extra_argument':
        child['CommandLine'] += ' foreign-command'
    opened = []
    class Lease:
        def __init__(self, pid, expected):
            if change == 'missing_parent' and pid == 1234:
                raise desktop().DesktopError('process_missing')
            self.created_at = (300 if change == 'reused_parent' else 100) if pid == 1234 else 200
            self.handle = pid
            self.kernel = SimpleNamespace(WaitForSingleObject=lambda *args: 258)
            opened.append(pid)
        def close(self):
            pass
    control = desktop().WindowsController()
    count = [0]
    def records():
        count[0] += 1
        fresh_child = dict(child)
        if change == 'changed_parent' and count[0] > 1:
            fresh_child['ParentProcessId'] = 9876
        return [dict(parent), fresh_child]
    monkeypatch.setattr(control, '_processes', records)
    monkeypatch.setattr(desktop(), 'ProcessLease', Lease)
    if change == 'none':
        with control.claim(root, {}, 'noadmin'):
            assert [(pid, group) for pid, _, group, _ in control.leases] == [(1234, 'opensearch'), (4321, 'opensearch')]
    else:
        with pytest.raises(desktop().DesktopError, match='process_identity'):
            with control.claim(root, {}, 'noadmin'):
                pytest.fail('Unproven console descendant was accepted')


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows command lines')
@pytest.mark.parametrize('extra', [['--pgdata', 'foreign'], ['--pgdata=foreign'], ['-c', 'data_directory=foreign']])
def test_postgresql_main_with_additional_storage_options_is_not_owned(tmp_path, extra):
    import subprocess
    root = tmp_path / 'install'
    image = root / 'pgsql/bin/postgres.exe'
    command = subprocess.list2cmdline([str(image), '-D', str(root / 'data/postgresql'), *extra])
    assert desktop().WindowsController()._classify(root, str(image), command) is None
