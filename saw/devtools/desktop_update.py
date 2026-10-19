"""Private desktop worker; verified media only, with no service registration."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET


def _module(name):
    loaded = sys.modules.get('saw.devtools.' + name)
    if loaded is not None:
        return loaded
    spec = importlib.util.spec_from_file_location('_desktop_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


backend = _module('offline_update')
health = _module('runtime_health')
diagnostics = _module('update_diagnostics')
SERVICE_PATHS = {
    'saw': 'service/saw-service.exe',
    'saw-postgresql': 'service/saw-postgresql.exe',
    'saw-opensearch': 'opensearch-2.19.6/bin/opensearch-service-x64.exe',
}
MESSAGES = {
    'validate': '설치와 새 매체를 확인하고 있습니다.',
    'stop': '계정과 자료를 보존하기 위해 서버를 중지하고 있습니다.',
    'plan': '복구 공간과 중지 상태를 확인하고 있습니다.',
    'apply': '전체 복구본을 만들고 새 프로그램을 적용하고 있습니다.',
    'restore': '보관한 시점으로 전체 설치를 복구하고 있습니다.',
    'start': '데이터베이스, 검색, 웹 서버를 시작하고 있습니다.',
    'health': '저장소와 HTTPS 응답을 확인하고 있습니다.',
    'administrator_required': '관리자 권한으로 다시 검사해야 합니다. 아직 설치 내용을 검증하지 않았습니다.',
    'ready': '확인이 끝났습니다. 작업 내용을 확인한 뒤 진행하세요.',
    'completed': '기동 확인이 끝났습니다. 브라우저에서 로그인과 자료를 확인하세요.',
    'failed': '작업이 완료되지 않았습니다. 설치와 복구 폴더를 그대로 보관하세요.',
}


MESSAGES.update({
    'maintenance_confirmation_required': '진행 중인 작업을 저장하고 점검 중 사용을 중지한다는 항목을 확인하세요.',
    'recovery_confirmation_required': '복구 시점 이후의 계정과 자료 변경이 별도 보관된다는 항목을 확인하세요.',
    'recovery_path_required': '설치와 별도로 보관할 복구 폴더를 선택하세요.',
    'recovery_headroom_insufficient': '전체 복구를 위한 추가 공간이 부족합니다. 공간을 확보한 뒤 다시 검사하세요.',
    'foreign_service': '다른 설치의 서비스가 확인됐습니다. 선택한 설치 폴더와 서비스 등록을 관리자에게 확인하세요.',
    'process_identity_unverified': '실행 중인 프로세스가 이 설치 소유인지 확인하지 못했습니다. 다른 프로그램을 종료하지 않았습니다.',
    'runtime_upgrade_unsupported': '이 매체는 실행 환경까지 변경합니다. 지원되는 별도 업그레이드 절차가 필요합니다.',
    'installation_mode_unverified': '완료된 설치 방식이 확인되지 않습니다. 설치 폴더와 기존 설치 상태를 확인하세요.',
    'snapshot_identity_unverified': '이 복구본은 선택한 설치 경로와 일치하지 않습니다. 해당 설치의 복구본을 선택하세요.',
    'snapshot_verification_failed': '복구본 파일이나 권한 검증에 실패했습니다. 복구본을 수정하지 말고 보관하세요.',
    'service_environment_unverified': '서비스에 별도 SAW 환경 설정이 있습니다. 기존 설정과 계정 연결을 관리자에게 확인하세요.',
    'service_configuration_unverified': '서비스 설정 경로가 확인되지 않습니다. 기존 설정을 보존하고 관리자에게 확인하세요.',
    'tracking_changed': '실행 추적 정보가 작업 중 달라졌습니다. 다른 제어 작업을 끝낸 뒤 다시 검사하세요.',
    'flush_failed': '검색 저장소의 안전한 저장을 확인하지 못했습니다. 저장소는 강제 종료하지 않았습니다.',
    'stop_failed': '전체 중지를 확인하지 못했습니다. 파일 적용을 진행하지 않았습니다.',
    'start_failed': '서버 기동을 확인하지 못했습니다. 복구본을 보관하고 기동 상태를 확인하세요.',
    'health_failed': '저장소 또는 HTTPS 검증에 실패했습니다. 로그인과 운영 준비가 완료된 상태가 아닙니다.',
    'baseline_required': '구형 설치를 확인하려면 원래 설치에 사용한 매체 폴더를 선택하세요.',
    'source_changed': '설치된 프로그램이 배포본과 다릅니다. 변경 파일을 보존하고 원래 매체를 확인하세요.',
    'unsafe_access': '설치 접근 권한을 확인하지 못했습니다. 권한을 자동 변경하지 않았으니 관리자에게 확인하세요.',
    'unsafe_owner': '설치 파일 소유자를 확인하지 못했습니다. 관리자에게 소유권을 확인하세요.',
    'still_running': '설치에 연결된 프로세스나 포트가 아직 사용 중입니다. 다른 제어 작업을 끝내고 다시 검사하세요.',
    'maintenance_busy': '같은 설치의 다른 설치·업데이트 작업이 진행 중입니다. 해당 작업이 끝난 뒤 다시 시도하세요.',
    'insufficient_space': '작업 공간이 부족합니다. 설치와 복구본을 지우지 말고 별도 공간을 확보하세요.',
    'unsupported_configuration': '외부 저장소 또는 변경된 구성이 확인됐습니다. 자동 업데이트 지원 범위를 확인하세요.',
    'unsafe_paths': '설치·매체·복구·작업 폴더를 서로 겹치지 않는 로컬 경로로 선택하세요.',
    'restore_interrupted': '복구가 중단됐습니다. 복구본과 별도 보관 폴더를 유지하고 같은 복구본으로 다시 복구하세요.',
    'restore_journal_invalid': '복구 작업 기록 또는 보관본이 달라졌습니다. 폴더를 이동하거나 덮어쓰지 말고 관리자에게 확인하세요.',
    'recovery_not_fresh': '기존 복구본을 보존하고 새 복구 위치를 선택하세요. 되돌리려면 복구 버튼을 사용하세요.',
    'state_write_failed': '상태 결과를 저장하지 못했습니다. 성공으로 판단하지 말고 작업 공간과 복구본을 확인하세요.',
    'unsupported_shell_path': '이 설치 경로에는 자동 기동에서 지원하지 않는 문자가 있습니다. 기존 설치를 옮기거나 수정하지 마세요.',
})


def _failure_code(error, phase):
    explicit = getattr(error, 'code', None)
    if isinstance(explicit, str) and re.fullmatch(r'[a-z_]{1,64}', explicit):
        return explicit
    if isinstance(error, DesktopError):
        return error.code if re.fullmatch(r'[a-z_]{1,64}', error.code) else phase + '_failed'
    if isinstance(error, backend.UpdateError):
        message = str(error)
        for prefix, code in (
            ('Legacy installations require', 'baseline_required'),
            ('Installed application/runtime differs', 'source_changed'),
            ('Unexpected installed application file', 'source_changed'),
            ('Installation access policy', 'unsafe_access'),
            ('All installed application and storage ports', 'still_running'),
            ('Installed processes or services', 'still_running'),
            ('A tracked process', 'still_running'),
            ('PostgreSQL still has', 'still_running'),
            ('Another installation maintenance', 'maintenance_busy'),
            ('Insufficient free space', 'insufficient_space'),
            ('External', 'unsupported_configuration'),
            ('Customized', 'unsupported_configuration'),
            ('Only the bundled local', 'unsupported_configuration'),
            ('Recovery point files or access policies', 'snapshot_verification_failed'),
        ):
            if message.startswith(prefix):
                return code
    return phase + '_failed'
class DesktopError(ValueError):
    def __init__(self, code, *, diagnostics=None):
        self.code = code
        self.diagnostics = diagnostics or {}
        super().__init__(code)


def _read_json(path, limit=1024 * 1024):
    if not path.is_file() or path.stat().st_size > limit or path.stat().st_nlink != 1:
        raise DesktopError('invalid_metadata')
    return json.loads(path.read_text(encoding='utf-8-sig'))


def _current_sid():
    return backend._ps('[Security.Principal.WindowsIdentity]::GetCurrent().User.Value')


def _check_access(path, current, relative=Path('.'), service_mode=False, private=False):
    if os.name != 'nt':
        if private and path.stat().st_mode & 0o077:
            raise DesktopError('unsafe_access')
        return
    violations = backend._access_violations(path, current, relative, service_mode, private)
    if violations:
        report = {'scope': 'state' if private else 'installation', 'checked': 1,
                  'violations': len(violations), 'truncated': len(violations) > 30,
                  'items': [{'path': backend._safe_access_path(relative), **item} for item in violations[:30]]}
        error = DesktopError('unsafe_owner' if violations[0]['reason'] == 'untrusted_owner' else 'unsafe_access')
        error.diagnostics = report
        raise error


def _state_directory(state_dir, paths):
    try:
        state = backend._path(state_dir)
        for path in paths:
            backend._separate(state, path)
        current = _current_sid() if os.name == 'nt' else ''
        _check_access(state, current, private=True)
        if os.name == 'nt' and not backend._acl(state).startswith('D:P'):
            raise DesktopError('unsafe_state_directory')
        for name in ('state.json',):
            target = state / name
            if target.exists():
                backend._path(target, existing=False)
                if not target.is_file() or target.stat().st_nlink != 1:
                    raise DesktopError('unsafe_state_directory')
                _check_access(target, current, private=True)
        return state
    except Exception:
        raise DesktopError('unsafe_state_directory') from None


class State:
    def __init__(self, directory, action, root, recovery):
        self.directory = directory
        self.value = {'schema': 'saw.desktop-update/1', 'action': action, 'phase': 'validate',
                      'status': 'working', 'code': 'working', 'install_root': str(root),
                      'requires_admin': False, 'needs_acceptance': False, 'operation_id': uuid.uuid4().hex}
        if recovery is not None:
            self.value['recovery_point'] = str(recovery)

    def write(self, phase, status='working', code=None, **fields):
        self.value.update(fields, phase=phase, status=status, code=code or status,
                          message=MESSAGES.get(code or phase, MESSAGES.get(phase, MESSAGES['failed'])))
        temporary = self.directory / ('state-' + uuid.uuid4().hex + '.writing')
        with open(temporary, 'x', encoding='utf-8', opener=backend._private_file_fd) as stream:
            json.dump(self.value, stream, ensure_ascii=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.directory / 'state.json')
        return dict(self.value)


def _service_matches(root, record):
    name = record.get('Name')
    if name not in SERVICE_PATHS:
        return False
    executable = str(root / SERVICE_PATHS[name])
    suffix = r'\s+//RS//saw-opensearch' if name == 'saw-opensearch' else ''
    return bool(re.fullmatch(r'\s*"?' + re.escape(executable) + r'"?' + suffix + r'\s*',
                             str(record.get('PathName', '')), re.IGNORECASE))


def _mode(root, identity, *, verified_installation=None):
    physical = verified_installation or root
    services = identity['services']
    selected = [entry for entry in services if entry.get('Name') in SERVICE_PATHS]
    owned = [entry for entry in services if str(root).casefold() in str(entry.get('PathName', '')).casefold()]
    markers = any((physical / ('service/' + name + extension)).exists()
                  for name in ('saw-service', 'saw-postgresql') for extension in ('.exe', '.xml'))
    journal = physical / '.saw-install-state.json'
    host = 'localhost'
    if journal.exists():
        saved = _read_json(journal)
        options = saved.get('options', {})
        if (saved.get('schema') != 'saw.install-state/1' or
                Path(saved.get('root', '')) != root or saved.get('status') != 'complete' or
                type(options.get('noAdmin')) is not bool or options.get('noServices') is not False):
            raise DesktopError('installation_mode_unverified')
        mode = 'noadmin' if options['noAdmin'] else 'service'
        host = options.get('hostName', 'localhost')
    else:
        mode = 'service' if markers or owned else 'noadmin'
    if mode == 'service':
        if len(selected) != 3 or any(not _service_matches(root, entry) for entry in selected) or len(owned) != 3:
            raise DesktopError('foreign_service')
    elif markers or owned:
        raise DesktopError('installation_mode_unverified')
    if not isinstance(host, str) or not health._tls_name_valid(host):
        raise DesktopError('invalid_host')
    return mode, host


def _static_access(root):
    current = _current_sid() if os.name == 'nt' else ''
    service_mode = (root / 'service/saw-postgresql.exe').is_file()
    paths = {root}
    for relative in ('app', 'venv', 'pgsql', 'llm-runtime', 'tls', 'secrets', 'service',
                     'opensearch-2.19.6/bin', 'opensearch-2.19.6/lib', 'opensearch-2.19.6/jdk',
                     'opensearch-2.19.6/plugins', 'opensearch-2.19.6/config', 'run'):
        directory = root / relative
        if directory.exists():
            paths.update(backend._tree_paths(directory))
    for relative in ('.saw-install-state.json', 'installed-release-manifest.json', 'saw-ctl.json',
                     'data', 'data/postgresql', 'data/postgresql/PG_VERSION',
                     'data/postgresql/postgresql.conf', 'data/postgresql/postgresql.auto.conf'):
        candidate = root / relative
        if candidate.exists():
            backend._path(candidate, existing=False)
            paths.add(candidate)
    for path in paths:
        _check_access(path, current, path.relative_to(root), service_mode)


def _verify_source(root, bundle, baseline_dir, action, *, verified_application_config=None):
    _static_access(root)
    backend._tree_paths(bundle)
    backend._manifest.verify(bundle)
    previous = backend._baseline(root, baseline_dir) if action != 'restore' else None
    candidate = _read_json(bundle / 'release-manifest.json', 8 * 1024 * 1024)
    if any(candidate.get('metadata', {}).get(key) != value for key, value in backend.PINS.items()):
        raise DesktopError('runtime_upgrade_unsupported')
    if previous is not None and backend._runtime_rows(previous) != backend._runtime_rows(candidate):
        raise DesktopError('runtime_upgrade_unsupported')
    if previous is not None:
        backend._installed_source(root, previous)
    backend._installed_runtime(root, bundle)
    if action in ('inspect', 'apply'):
        backend._migration_chain(bundle, previous, candidate)
    _, cfg = backend._config(root, verified_application_config=verified_application_config)
    return cfg


def _verify_snapshot(root, recovery):
    if recovery is None:
        raise DesktopError('recovery_path_required')
    backend._access_gate(recovery, snapshot_root=recovery / 'installation')
    receipt = _read_json(recovery / 'recovery-point.json', 64 * 1024 * 1024)
    if receipt.get('schema') != 'saw.cold-recovery/1' or Path(receipt.get('install_root', '')) != root:
        raise DesktopError('snapshot_identity_unverified')
    if backend._inventory(recovery / 'installation') != receipt.get('files'):
        raise DesktopError('snapshot_verification_failed')
    return receipt



def _inspection_publish(state, report, **fields):
    backend._json(state.directory / 'inspection-details.json', report.document(), unique=True)
    state.write('validate', diagnostic_summary=report.summary(), **fields)


def _require_path_access(path, rights):
    """Request exact access on an existing object without modifying it."""
    if os.name != 'nt':
        target = path.parent if rights & 0x10000 else path
        needed = os.W_OK | (os.X_OK if target.is_dir() else 0)
        if not os.access(target, needed):
            raise DesktopError('recovery_parent_access', diagnostics={
                'location': str(path), 'expected': 'required filesystem mutation access',
                'actual': 'access unavailable', 'requested_mask': rights})
        return
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
    kernel.CreateFileW.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    handle = kernel.CreateFileW(str(path), rights, 7, None, 3, 0x02000000, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        raise DesktopError('recovery_parent_access', diagnostics={
            'location': str(path), 'expected': 'required filesystem mutation access',
            'actual': 'access unavailable (' + str(ctypes.get_last_error()) + ')',
            'requested_mask': rights})
    kernel.CloseHandle(handle)


def _require_directory_write(path):
    """Require add-file/add-subdirectory rights, without full-control access."""
    _require_path_access(path, 0x6)


def _require_remove_access(path):
    """Rename/delete accepts object DELETE or parent FILE_DELETE_CHILD."""
    if os.name != 'nt':
        _require_path_access(path.parent, 0x40)
        return
    try:
        _require_path_access(path, 0x10000)
        return
    except DesktopError as error:
        if error.code != 'recovery_parent_access':
            raise
    try:
        _require_path_access(path.parent, 0x40)
        return
    except DesktopError as error:
        if error.code != 'recovery_parent_access':
            raise
    raise DesktopError('recovery_parent_access', diagnostics={
        'location': str(path), 'expected': 'DELETE on object or DELETE_CHILD on parent',
        'actual': 'neither rename/delete access alternative is available',
        'requested_mask': 0x10000, 'alternative_parent_mask': 0x40})


def _recovery_preflight(root, bundle, recovery, action, report, *, already_restored=False):
    if action == 'start':
        report.set('recovery', code='recovery_not_required',
                   reason='설치본 다시 시작은 새 복구본을 만들지 않습니다. 복구본은 검증하지 않았습니다.',
                   actual='새 복구본 불필요')
        return {'snapshot_required': False, 'required_with_restore_headroom_bytes': 0}
    paths = backend._tree_paths(root)
    rows = [{'path': p.relative_to(root).as_posix(), 'directory': p.is_dir(),
             **({'bytes': p.stat().st_size} if p.is_file() else {})} for p in paths]
    size = sum(row.get('bytes', 0) for row in rows)
    candidate = _read_json(bundle / 'release-manifest.json', 8 * 1024 * 1024)
    app = sum(row['bytes'] for row in candidate['files'] if row['path'].startswith('app/'))
    needed = 2 * size + app + sum(row.get('bytes', 0) for row in rows if row['path'].startswith('app/var/')) + 128 * 1024 * 1024
    selected = recovery or root.with_name('.saw-recovery-preview')
    pending = None
    if selected.exists():
        if action == 'apply':
            raise DesktopError('recovery_not_fresh', diagnostics={'location': str(selected), 'expected': 'fresh directory', 'actual': 'already exists'})
        if action in ('inspect', 'restore'):
            receipt = _verify_snapshot(root, selected)
            backend._access_gate(selected / 'installation', check_copy_semantics=True)
            needed = sum(row.get('bytes', 0) for row in receipt['files']) + 64 * 1024 * 1024
            if action == 'restore':
                pending = backend._pending_restore(root, selected)
                if pending and pending['actual_phase'] in ('staged', 'root_retained', 'restored'):
                    needed = 0
    elif action == 'restore':
        raise DesktopError('snapshot_verification_failed')
    if not selected.parent.is_dir() or selected.drive.casefold() != root.drive.casefold():
        raise DesktopError('unsafe_paths', diagnostics={'location': str(selected), 'expected': 'same volume; existing parent', 'actual': 'unsupported recovery location'})
    backend._separate(root, bundle, selected)
    for prefix in ('.saw-r-', '.saw-k-'):
        sibling = root.with_name(prefix + '0' * 12)
        backend._preflight_rows(sibling, rows)
    backend._preflight_rows(selected / 'installation', rows)
    backend._preflight_copy(bundle / 'app', selected / 'new-app')
    backend._preflight_copy(bundle / 'app', root / 'app')
    for name in ('recovery-point.json', 'update-result.json'):
        backend._preflight_json(selected / name)
    for name in ('restore-journal.json', 'restore-result-' + '0' * 12 + '.json'):
        backend._preflight_json(selected / name, unique=True)
    for name in ('saw-ctl.ps1', 'installed-release-manifest.json', '.saw-u-' + '0' * 12):
        backend._windows_path_limit(root / name, directory=False)
    if already_restored:
        needed = 0  # Verified stage was allocated before the interrupted rename.
    if not already_restored:
        if selected.exists():
            _require_path_access(selected, 0x2)  # FILE_ADD_FILE for private publication.
            publications = [selected / 'restore-journal.json']
            if pending and pending['actual_phase'] != 'complete':
                publications.append(selected / ('restore-result-' + pending['token'] + '.json'))
            for path in publications:
                if path.exists():
                    _require_remove_access(path)
        else:
            _require_path_access(selected.parent, 0x4)  # FILE_ADD_SUBDIRECTORY.
        if action in ('inspect', 'apply'):
            _require_directory_write(root)
            if (root / 'app').exists():
                _require_remove_access(root / 'app')
            for name in ('saw-ctl.ps1', 'installed-release-manifest.json'):
                path = root / name
                if path.exists():
                    # The replacement receives this DACL before its public bytes.
                    _require_path_access(path, 0x2)  # FILE_WRITE_DATA.
                    _require_remove_access(path)
        phase = pending['actual_phase'] if pending else None
        if action != 'restore' or phase != 'restored':
            _require_path_access(root.parent, 0x4)
            if root.exists():
                _require_remove_access(root)
            if action == 'restore' and phase in ('staged', 'root_retained'):
                _require_remove_access(Path(pending['stage']))
    free = backend.shutil.disk_usage(root.parent).free
    if free < needed:
        raise DesktopError('recovery_headroom_insufficient', diagnostics={
            'location': str(root.parent), 'expected': str(needed) + ' bytes', 'actual': str(free) + ' bytes'})
    report.set('recovery', reason='복구 경로·전체 복원 공간 확인 완료. 중지 후 파일과 공간을 다시 검사합니다.',
               location=str(selected), expected=str(needed) + ' bytes', actual=str(free) + ' bytes')
    return {'snapshot_bytes': size, 'required_with_restore_headroom_bytes': needed, 'free_bytes': free}


def _inspect_all(state, root, bundle, baseline, recovery, action, control, identity, *, already_restored=False):
    report = diagnostics.Inspection()
    report.set('paths', location=str(root))
    cfg = mode = host = previous = candidate = None

    def check(key, operation, success=None):
        try:
            value = operation()
            if report.rows[key]['status'] == 'not_run':
                report.set(key, **(success or {}))
            return True, value
        except Exception as error:
            report.error(key, error, _failure_code(error, key))
            return False, None

    media_ok, media_result = check('media', lambda: backend._manifest.verify(bundle), {'location': str(bundle)})
    registered = [entry for entry in identity['services'] if entry.get('Name') in SERVICE_PATHS]
    if not identity['admin'] and len(registered) == 3 and all(_service_matches(root, entry) for entry in registered):
        report.error('services', DesktopError('administrator_required'), 'administrator_required')
        report.set('overall', 'action_required', 'administrator_required', reason='관리자 권한으로 나머지 검사를 실행해야 합니다.')
        _inspection_publish(state, report, mode='service', requires_admin=True)
        return report, None, 'service', 'localhost'

    # Live stores can rotate files during inspection; each bounded retry scans every current ACL.
    # Cold backups and mutation guards retain the backend's strict, single-scan default.
    access_ok, access_detail = check('access', lambda: backend._access_gate(
        root, check_copy_semantics=action in ('inspect', 'apply'), retry_transient=True))
    if access_ok and access_detail:
        actual = str(access_detail.get('checked', 0)) + '개 검사'
        attempts = access_detail.get('attempts')
        if type(attempts) is int and 1 <= attempts <= 3:
            actual += ' · 전체 검사 시도 ' + str(attempts) + '회'
        report.set('access', actual=actual, diagnostics=access_detail)
    if access_ok:
        stores_ok, config_result = check('stores', lambda: backend._config(root,
            verified_application_config=(recovery / 'installation/app/.env') if action == 'restore' and recovery and not (root / 'app').exists() else None))
        if stores_ok:
            _, cfg = config_result
        mode_ok, mode_result = check('services', lambda: _mode(root, identity))
        if mode_ok:
            mode, host = mode_result
            # Claim is the final service/process check, after runtime validation.
            report.rows['services']['status'] = 'not_run'
        if action == 'restore':
            baseline_ok, previous = check('baseline', lambda: _verify_snapshot(root, recovery),
                                          {'reason': '선택한 복구본의 설치 경로와 전체 파일 확인 완료'})
        else:
            baseline_ok, previous = check('baseline', lambda: backend._baseline(root, baseline),
                                          {'location': str(root / 'installed-release-manifest.json') if baseline is None else str(baseline)})
            if baseline_ok:
                baseline_ok, _ = check('baseline', lambda: backend._installed_source(root, previous))
        if media_ok and baseline_ok:
            def runtime():
                candidate = _read_json(bundle / 'release-manifest.json', 8 * 1024 * 1024)
                if any(candidate.get('metadata', {}).get(k) != v for k, v in backend.PINS.items()):
                    raise DesktopError('runtime_upgrade_unsupported')
                if action != 'restore' and backend._runtime_rows(previous) != backend._runtime_rows(candidate):
                    raise DesktopError('runtime_upgrade_unsupported')
                backend._installed_runtime(root, bundle)
                if action in ('inspect', 'apply'):
                    try:
                        backend._migration_chain(bundle, previous, candidate)
                    except backend.UpdateError:
                        raise DesktopError('migration_unsupported') from None
                if mode == 'noadmin' and any(c in str(root) for c in ('%', '!', chr(13), chr(10))):
                    raise DesktopError('unsupported_shell_path')
            runtime_ok, _ = check('configuration_runtime', runtime)
        else:
            runtime_ok = False
        if cfg is not None and mode is not None and runtime_ok:
            def services():
                if mode == 'service' and not identity['admin']:
                    raise DesktopError('administrator_required')
                with control.claim(root, cfg, mode):
                    pass
            check('services', services)
        if media_ok:
            check('recovery', lambda: _recovery_preflight(root, bundle, recovery, action, report, already_restored=already_restored))
    failed = bool(report.errors) or any(row['status'] != 'pass' for key, row in report.rows.items() if key != 'overall')
    report.set('overall', 'fail' if failed else 'pass', 'preflight_failed' if failed else 'ready',
               reason='문제를 해결하고 다시 점검하세요. 서버를 중지하지 않았습니다.' if failed else '사전 점검 통과. 적용 시 잠금 안에서 다시 검증합니다.')
    _inspection_publish(state, report, **({'mode': mode} if mode else {}), requires_admin=mode == 'service' and not identity['admin'],
                        **({'app_url': 'https://' + host + ':' + str(cfg['port']) + '/'} if cfg and host else {}))
    return report, cfg, mode, host

def run(action, install_root, bundle_dir, state_dir, *, baseline_dir=None, recovery_point=None,
        maintenance_confirmed=False, confirm=False, controller=None):
    try:
        root, bundle = backend._path(install_root, existing=action != 'restore'), backend._path(bundle_dir)
        baseline = backend._path(baseline_dir) if baseline_dir else None
        recovery = backend._path(recovery_point, existing=False) if recovery_point else None
        paths = [root, bundle] + ([baseline] if baseline else []) + ([recovery] if recovery else [])
        directory = _state_directory(state_dir, paths)
        backend._separate(root, bundle, *([recovery] if recovery else []))
        if baseline is not None:
            backend._separate(root, baseline, *([recovery] if recovery else []))
    except Exception:
        raise DesktopError('unsafe_paths') from None
    state = State(directory, action, root, recovery)
    try:
        state.write('validate', current_step='validate')
        if action not in ('inspect', 'apply', 'restore', 'start'):
            raise DesktopError('invalid_action')
        if action in ('apply', 'restore') and not maintenance_confirmed:
            raise DesktopError('maintenance_confirmation_required')
        if action == 'restore' and not confirm:
            raise DesktopError('recovery_confirmation_required')
        if action in ('apply', 'restore') and recovery is None:
            raise DesktopError('recovery_path_required')
        control = controller or WindowsController()
        identity = control.identity()
        with backend._maintenance(root, allow_missing=action == 'restore'):
            resumed_restore = False
            if action == 'restore' and not root.exists():
                # Only a verified interrupted transaction can restore a missing name.
                # No service is stopped here; backend requires all related processes,
                # ports and registered services already stopped before either rename.
                backend._manifest.verify(bundle)
                _verify_snapshot(root, recovery)
                mode, host = _mode(root, identity, verified_installation=recovery / 'installation')
                state.write('validate', mode=mode, requires_admin=mode == 'service' and not identity['admin'])
                if mode == 'service' and not identity['admin']:
                    raise DesktopError('administrator_required')
                pending = backend._pending_restore(root, recovery)
                if pending is None or pending['actual_phase'] != 'root_retained':
                    raise DesktopError('restore_journal_invalid')
                _require_path_access(root.parent, 0x4)
                _require_remove_access(Path(pending['stage']))
                _require_path_access(recovery, 0x2)
                for name in ('restore-journal.json', 'restore-result-' + pending['token'] + '.json'):
                    publication = recovery / name
                    if publication.exists():
                        _require_remove_access(publication)
                state.write('restore', current_step='restore_swap', recovery_verified=True,
                            retained_installation=pending['retained_installation'])
                result = backend.restore.__wrapped__(root, recovery, confirm=True,
                    progress=lambda step: state.write('restore', current_step=step))
                if result.get('status') != 'restored_stopped':
                    raise DesktopError('unexpected_backend_result')
                state.value['retained_installation'] = result['retained_installation']
                resumed_restore = True
            if os.path.lexists(root / 'installed-release-manifest.json'):
                baseline = None
            report, cfg, mode, host = _inspect_all(state, root, bundle, baseline, recovery, action, control, identity, already_restored=resumed_restore)
            if state.value.get('requires_admin'):
                if action == 'inspect':
                    return state.write('ready', 'ready', 'administrator_required')
                raise DesktopError('administrator_required')
            if report.errors:
                raise report.errors[0]
            if report.rows['overall']['status'] != 'pass':
                raise DesktopError('preflight_failed')
            with control.claim(root, cfg, mode):
                if action == 'inspect':
                    return state.write('ready', 'ready')
                if action in ('apply', 'restore') and not resumed_restore:
                    state.write('stop', current_step='stop', last_completed_step='preflight')
                    control.stop(root, cfg, mode)
                    state.write('plan', current_step='snapshot', last_completed_step='stop')
                    backend._stopped(root, cfg)
                    if action == 'apply':
                        plan = backend.plan(root, bundle, baseline)
                        restore_headroom = plan['required_free_bytes'] + plan['snapshot_bytes'] + 64 * 1024 * 1024
                        if backend.shutil.disk_usage(root.parent).free < restore_headroom:
                            raise DesktopError('recovery_headroom_insufficient')
                        plan['required_with_restore_headroom_bytes'] = restore_headroom
                        state.write('apply', plan=plan, current_step='apply')
                        result = backend.apply.__wrapped__(root, bundle, recovery, baseline)
                        if result.get('status') != 'applied_stopped_schema_pending':
                            raise DesktopError('unexpected_backend_result')
                    else:
                        state.write('restore', current_step='restore')
                        result = backend.restore.__wrapped__(root, recovery, confirm=True,
                            progress=lambda step: state.write('restore', current_step=step))
                        if result.get('status') != 'restored_stopped':
                            raise DesktopError('unexpected_backend_result')
                        state.value['retained_installation'] = result['retained_installation']
                    # Verify the source selected by the new/restored installed identity before launch.
                    if action == 'restore':
                        # The core checked the complete snapshot and its ACLs before replacement.
                        _static_access(root)
                        backend._installed_runtime(root, bundle)
                        _, cfg = backend._config(root)
                    else:
                        cfg = _verify_source(root, bundle, None, 'start')
                else:
                    backend._stopped(root, cfg)
                if mode == 'service':
                    control._service_configuration(root, cfg)
                    control._service_environment()
                state.write('start', needs_acceptance=True, current_step='start', last_completed_step=action if action in ('apply', 'restore') else 'preflight')
                control.start(root, cfg, mode)
                state.write('health', current_step='health', last_completed_step='start')
                if not control.healthy(root, cfg, host):
                    raise DesktopError('health_failed')
                return state.write('completed', 'completed', needs_acceptance=True, current_step='completed', last_completed_step='health')
    except Exception as error:
        code = _failure_code(error, state.value['phase'])
        failed_phase = state.value['phase']
        fields = {'failed_phase': failed_phase, 'current_step': state.value.get('current_step', 'validate'), 'can_retry': True}
        if recovery is not None and (recovery / 'recovery-point.json').is_file():
            try:
                _verify_snapshot(root, recovery)
                fields['recovery_verified'] = True
                pending = backend._pending_restore(root, recovery)
                if pending is not None:
                    fields['retained_installation'] = pending['retained_installation']
            except Exception:
                fields['recovery_verified'] = False
        try:
            return state.write('failed', 'failed', code, **fields)
        except Exception:
            # Never report success when the private result channel is unavailable.
            state.value.update(phase='failed', status='failed', code='state_write_failed', **fields)
            return dict(state.value)


class ProcessLease:
    """Keep the kernel object alive so PID reuse can never redirect termination."""
    def __init__(self, pid, expected_image, *, terminate=True):
        from ctypes import wintypes as w
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        self.kernel.OpenProcess.restype = w.HANDLE
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.kernel.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD)]
        self.kernel.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
        self.kernel.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
        self.handle = self.kernel.OpenProcess(0x101000 | (1 if terminate else 0), False, pid)
        if not self.handle:
            raise DesktopError('process_missing' if ctypes.get_last_error() == 87 else 'process_identity_unverified')
        try:
            size = w.DWORD(32768)
            image = ctypes.create_unicode_buffer(size.value)
            if not self.kernel.QueryFullProcessImageNameW(self.handle, 0, image, ctypes.byref(size)):
                raise DesktopError('process_identity_unverified')
            canonical = lambda value: os.path.normcase(os.path.realpath(value))
            if canonical(image.value) != canonical(expected_image):
                raise DesktopError('process_identity_unverified')
            self.kernel.GetProcessTimes.argtypes = [w.HANDLE, *([ctypes.POINTER(w.FILETIME)] * 4)]
            self.kernel.GetProcessTimes.restype = w.BOOL
            created, ended, kernel_time, user_time = (w.FILETIME() for _ in range(4))
            if not self.kernel.GetProcessTimes(self.handle, ctypes.byref(created), ctypes.byref(ended),
                                               ctypes.byref(kernel_time), ctypes.byref(user_time)):
                raise DesktopError('process_identity_unverified')
            self.created_at = (created.dwHighDateTime << 32) | created.dwLowDateTime
        except BaseException:
            self.close()
            raise

    def stop(self):
        if self.kernel.WaitForSingleObject(self.handle, 0) == 0:
            return
        if not self.kernel.TerminateProcess(self.handle, 1):
            raise DesktopError('stop_failed')
        if self.kernel.WaitForSingleObject(self.handle, 30000) != 0:
            raise DesktopError('stop_failed')

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class ServiceLease:
    """An SCM handle prevents name deletion/recreation from redirecting control."""
    def __init__(self, name, root):
        from ctypes import wintypes as w
        self.api = ctypes.WinDLL('advapi32', use_last_error=True)
        self.api.OpenSCManagerW.argtypes = [w.LPCWSTR, w.LPCWSTR, w.DWORD]
        self.api.OpenSCManagerW.restype = w.HANDLE
        self.api.OpenServiceW.argtypes = [w.HANDLE, w.LPCWSTR, w.DWORD]
        self.api.OpenServiceW.restype = w.HANDLE
        self.api.CloseServiceHandle.argtypes = [w.HANDLE]
        self.api.QueryServiceConfigW.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD)]
        self.api.QueryServiceStatusEx.argtypes = [w.HANDLE, w.DWORD, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD)]
        self.api.ControlService.argtypes = [w.HANDLE, w.DWORD, ctypes.c_void_p]
        self.api.StartServiceW.argtypes = [w.HANDLE, w.DWORD, ctypes.c_void_p]
        manager = self.api.OpenSCManagerW(None, None, 1)
        if not manager:
            raise DesktopError('service_access_failed')
        try:
            self.handle = self.api.OpenServiceW(manager, name, 0x35)
        finally:
            self.api.CloseServiceHandle(manager)
        if not self.handle:
            raise DesktopError('service_access_failed')
        try:
            class Config(ctypes.Structure):
                _fields_ = [('kind', w.DWORD), ('start', w.DWORD), ('error', w.DWORD),
                            ('binary', w.LPWSTR), ('group', w.LPWSTR), ('tag', w.DWORD),
                            ('dependencies', ctypes.c_void_p), ('account', w.LPWSTR), ('display', w.LPWSTR)]
            needed = w.DWORD()
            self.api.QueryServiceConfigW(self.handle, None, 0, ctypes.byref(needed))
            buffer = ctypes.create_string_buffer(needed.value)
            if not needed.value or not self.api.QueryServiceConfigW(self.handle, buffer, needed.value, ctypes.byref(needed)):
                raise DesktopError('service_identity_unverified')
            config = ctypes.cast(buffer, ctypes.POINTER(Config)).contents
            dependencies = []
            if config.dependencies:
                address = ctypes.addressof(buffer)
                offset = config.dependencies - address
                unit = ctypes.sizeof(ctypes.c_wchar)
                available = ctypes.sizeof(buffer) - offset
                if offset < 0 or available < unit or offset % unit:
                    raise DesktopError('service_identity_unverified')
                raw = ctypes.wstring_at(config.dependencies, available // unit)
                if not raw.startswith('\0'):
                    end = raw.find('\0\0')
                    if end < 0:
                        raise DesktopError('service_identity_unverified')
                    dependencies = raw[:end].split('\0')
            self._verify_configuration(name, root, config.binary, config.kind, config.account, dependencies)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _verify_configuration(name, root, binary, kind, account, dependencies):
        if not _service_matches(root, {'Name': name, 'PathName': binary}):
            raise DesktopError('foreign_service')
        normalized = str(account or '').strip().casefold()
        allowed = ({r'nt authority\networkservice', r'nt authority\network service'}
                   if name == 'saw-postgresql' else {'localsystem', r'nt authority\system'})
        if kind != 0x10 or normalized not in allowed:
            raise DesktopError('service_identity_unverified')

        dependencies = [value.casefold() for value in dependencies]
        if len(dependencies) != len(set(dependencies)):
            raise DesktopError('service_identity_unverified')
        expected = {'saw-postgresql', 'saw-opensearch'} if name == 'saw' else set()
        valid = (set(dependencies) <= {'tcpip', 'afd'} if name == 'saw-opensearch' else
                 set(dependencies) == expected)
        if not valid:
            raise DesktopError('service_identity_unverified')

    def _status_record(self):
        from ctypes import wintypes as w
        values = (w.DWORD * 9)()
        needed = w.DWORD()
        if not self.api.QueryServiceStatusEx(self.handle, 0, values, ctypes.sizeof(values), ctypes.byref(needed)):
            raise DesktopError('service_status_failed')
        return values[1], values[7]

    def process_id(self):
        state, pid = self._status_record()
        if state != 4 or not 0 < pid <= 0xffffffff:
            raise DesktopError('service_identity_unverified')
        return pid

    def status(self):
        return self._status_record()[0]

    def change(self, start):
        target, pending = (4, 2) if start else (1, 3)
        state = self.status()
        if state == target:
            return
        if state != pending:
            if state != (1 if start else 4):
                raise DesktopError('start_failed' if start else 'stop_failed')
            if start:
                success = self.api.StartServiceW(self.handle, 0, None)
            else:
                values = (ctypes.c_uint32 * 7)()
                success = self.api.ControlService(self.handle, 1, values)
            if not success:
                raise DesktopError('start_failed' if start else 'stop_failed')
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            state = self.status()
            if state == target:
                return
            if state != pending:
                raise DesktopError('start_failed' if start else 'stop_failed')
            time.sleep(1)
        raise DesktopError('start_failed' if start else 'stop_failed')

    def close(self):
        if self.handle:
            self.api.CloseServiceHandle(self.handle)
            self.handle = None


def _command_tokens(command):
    from ctypes import wintypes as w
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    shell.CommandLineToArgvW.argtypes = [w.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype = ctypes.POINTER(w.LPWSTR)
    count = ctypes.c_int()
    pointer = shell.CommandLineToArgvW(command, ctypes.byref(count))
    if not pointer:
        raise DesktopError('process_identity_unverified')
    try:
        return [pointer[index] for index in range(count.value)]
    finally:
        kernel = ctypes.WinDLL('kernel32')
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree(pointer)


class WindowsController:
    def __init__(self):
        self.leases = []
        self.absent = {}
        self.tracking = {}
        self.services = {}

    def identity(self):
        output = backend._ps("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=New-Object Text.UTF8Encoding($false); "
            "$identity=[Security.Principal.WindowsIdentity]::GetCurrent(); "
            "$principal=New-Object Security.Principal.WindowsPrincipal($identity); "
            "@{admin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); "
            "services=@(Get-CimInstance Win32_Service | Select-Object Name,PathName,State)} | ConvertTo-Json -Depth 4 -Compress")
        return json.loads(output)

    def _processes(self):
        return json.loads(backend._ps("$ErrorActionPreference='Stop'; "
            "[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false); "
            "ConvertTo-Json -InputObject @(Get-CimInstance Win32_Process | "
            "Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine) -Compress"))

    def _xml_policy(self, document, kind, root):
        allowed = {'id', 'name', 'description', 'executable', 'workingdirectory', 'startmode',
                   'onfailure', 'resetfailure', 'stoptimeout', 'logpath', 'log', 'env'}
        allowed.update({'arguments', 'depend', 'delayedAutoStart'} if kind == 'app' else
                       {'startarguments', 'stopexecutable', 'stoparguments', 'serviceaccount'})
        repeated = {'onfailure', 'env', 'depend'}
        if document.tag != 'service' or document.attrib or any(child.tag not in allowed for child in document):
            raise DesktopError('service_configuration_unverified')
        for name in allowed - repeated:
            if len(document.findall(name)) > 1:
                raise DesktopError('service_configuration_unverified')
        for child in document:
            if child.tag == 'env':
                if set(child.attrib) != {'name', 'value'} or list(child):
                    raise DesktopError('service_configuration_unverified')
            elif child.tag == 'onfailure':
                if set(child.attrib) != {'action', 'delay'} or child.get('action') != 'restart' or list(child):
                    raise DesktopError('service_configuration_unverified')
            elif child.tag == 'log':
                if child.attrib != {'mode': 'roll-by-size'} or any(item.tag not in ('sizeThreshold', 'keepFiles') for item in child):
                    raise DesktopError('service_configuration_unverified')
            elif child.tag == 'serviceaccount':
                if child.attrib or sorted(item.tag for item in child) != ['domain', 'user']:
                    raise DesktopError('service_configuration_unverified')
            elif child.attrib or list(child):
                raise DesktopError('service_configuration_unverified')
        environment = [(child.get('name'), child.get('value')) for child in document.findall('env')]
        system = Path(os.environ.get('SystemRoot', 'C:/Windows'))
        expected = [('PYTHONUTF8', '1')] if kind == 'app' else [('PATH',
            str(root / 'opensearch-2.19.6/jdk/bin') + ';' + str(system / 'System32') + ';' + str(system))]
        if environment != expected:
            raise DesktopError('service_configuration_unverified')

    @staticmethod
    def _runtime_override(name):
        name = name.upper()
        return (name.startswith(('SAW_', 'PYTHON', 'PG', 'PR_', 'OPENSEARCH')) or
                name in ('JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'CLASSPATH'))

    @staticmethod
    def _environment_values(values, kind, multi_kind):
        if (kind != multi_kind or not isinstance(values, (list, tuple)) or
                any(not isinstance(value, str) or '=' not in value or '\x00' in value
                    or not value.split('=', 1)[0] for value in values)):
            raise DesktopError('service_environment_unverified')
        names = [value.split('=', 1)[0].upper() for value in values]
        if len(names) != len(set(names)) or any(WindowsController._runtime_override(name) for name in names):
            raise DesktopError('service_environment_unverified')

    def _service_environment(self):
        import winreg
        try:
            location = r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, location, 0, winreg.KEY_READ) as key:
                for index in range(winreg.QueryInfoKey(key)[1]):
                    name, _, _ = winreg.EnumValue(key, index)
                    if self._runtime_override(name):
                        raise DesktopError('service_environment_unverified')
            for name in SERVICE_PATHS:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services' + '\\' + name,
                                    0, winreg.KEY_READ) as key:
                    try:
                        values, kind = winreg.QueryValueEx(key, 'Environment')
                    except FileNotFoundError:
                        continue
                    self._environment_values(values, kind, winreg.REG_MULTI_SZ)
        except DesktopError:
            raise
        except Exception:
            raise DesktopError('service_environment_unverified') from None

    @staticmethod
    def _verify_opensearch_procrun(root):
        """Read both views; every populated view must be complete and agree.

        Procrun x64 normally stores configuration in Registry32. Accept a
        verified legacy Registry64-only installation without copying values
        or changing service registration.
        """
        import winreg
        prefix = r'SOFTWARE\Apache Software Foundation\ProcRun 2.0\saw-opensearch\Parameters'
        home = root / 'opensearch-2.19.6'
        wanted = {'-Dopensearch.path.home': home, '-Dopensearch.path.conf': home / 'config'}
        profiles = []
        try:
            for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
                with ExitStack() as handles:
                    def open_key(branch):
                        return handles.enter_context(winreg.OpenKey(
                            winreg.HKEY_LOCAL_MACHINE, prefix + ('\\' + branch if branch else ''),
                            0, winreg.KEY_READ | view))
                    try:
                        parameters = open_key('')
                    except FileNotFoundError:
                        continue
                    java, start = open_key('Java'), open_key('Start')
                    try:
                        environment, kind = winreg.QueryValueEx(parameters, 'Environment')
                    except FileNotFoundError:
                        pass
                    else:
                        WindowsController._environment_values(environment, kind, winreg.REG_MULTI_SZ)
                    jvm, jvm_kind = winreg.QueryValueEx(java, 'Jvm')
                    working, working_kind = winreg.QueryValueEx(start, 'WorkingPath')
                    if (jvm_kind not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) or
                            working_kind not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) or
                            not isinstance(jvm, str) or not isinstance(working, str) or
                            not WindowsController._same_windows_path(jvm, home / 'jdk/bin/server/jvm.dll') or
                            not WindowsController._same_windows_path(working, home)):
                        raise DesktopError('service_configuration_unverified')
                    options = []
                    for name in ('Options', 'Options9'):
                        try:
                            values, kind = winreg.QueryValueEx(java, name)
                        except FileNotFoundError:
                            continue
                        if (kind != winreg.REG_MULTI_SZ or not isinstance(values, (tuple, list)) or
                                any(not isinstance(item, str) or not item or '\x00' in item
                                    or '\r' in item or '\n' in item for item in values)):
                            raise DesktopError('service_configuration_unverified')
                        options.extend(values)
                    canonical = []
                    counts = {name: 0 for name in wanted}
                    for option in options:
                        key, separator, value = option.partition('=')
                        if key in wanted:
                            counts[key] += 1
                            if value.startswith('"') and value.endswith('"') and len(value) >= 2:
                                value = value[1:-1]
                            if (not separator or '"' in value or
                                    not WindowsController._same_windows_path(value, wanted[key])):
                                raise DesktopError('service_configuration_unverified')
                            canonical.append(key + '=' + os.path.normcase(os.path.normpath(str(wanted[key]))))
                        else:
                            if any(name in option for name in wanted):
                                raise DesktopError('service_configuration_unverified')
                            canonical.append(option)
                    if any(count != 1 for count in counts.values()):
                        raise DesktopError('service_configuration_unverified')
                    profiles.append(canonical)
            if not profiles or any(profile != profiles[0] for profile in profiles[1:]):
                raise DesktopError('service_configuration_unverified')
        except Exception:
            raise DesktopError('service_configuration_unverified') from None

    def _service_configuration(self, root, cfg):
        def xml(name):
            path = root / ('service/' + name + '.xml')
            if not path.is_file() or path.stat().st_size > 65536:
                raise DesktopError('service_configuration_unverified')
            text = path.read_text(encoding='utf-8-sig')
            if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
                raise DesktopError('service_configuration_unverified')
            return ET.fromstring(text)
        try:
            pg = xml('saw-postgresql')
            self._xml_policy(pg, 'postgresql', root)
            expected = {'id': 'saw-postgresql', 'executable': str(root / 'pgsql/bin/postgres.exe'),
                        'startarguments': '-D "' + str(root / 'data/postgresql') + '"',
                        'stopexecutable': str(root / 'pgsql/bin/pg_ctl.exe'),
                        'stoparguments': 'stop -D "' + str(root / 'data/postgresql') + '" -m fast -w -t 120',
                        'workingdirectory': str(root / 'pgsql/bin'),
                        'serviceaccount/domain': 'NT AUTHORITY', 'serviceaccount/user': 'NetworkService'}
            if any((pg.findtext(key) or '').casefold() != value.casefold() for key, value in expected.items()):
                raise DesktopError('service_configuration_unverified')
            app = xml('saw-service')
            self._xml_policy(app, 'app', root)
            self._service_environment()
            if (app.findtext('id') != 'saw' or Path(app.findtext('executable', '')) != root / 'venv/Scripts/python.exe'
                    or Path(app.findtext('workingdirectory', '')) != root / 'app'):
                raise DesktopError('service_configuration_unverified')
            args = _command_tokens('placeholder ' + app.findtext('arguments', ''))[1:]
            expected_args = ['-m', 'saw.cli', 'serve', '--host', None, '--port', str(cfg['port']),
                             '--cert', str(root / 'tls/saw.crt'), '--key', str(root / 'tls/saw.key')]
            if len(args) != len(expected_args) or args[4] not in ('127.0.0.1', '0.0.0.0'):
                raise DesktopError('service_configuration_unverified')
            if any(wanted is not None and actual != wanted for actual, wanted in zip(args, expected_args)):
                raise DesktopError('service_configuration_unverified')
            self._verify_opensearch_procrun(root)
        except DesktopError:
            raise
        except Exception:
            raise DesktopError('service_configuration_unverified') from None

    @contextmanager
    def claim(self, root, cfg, mode):
        self.absent = {}
        self.tracking = {}
        try:
            if mode == 'service':
                self._service_configuration(root, cfg)
                for name in SERVICE_PATHS:
                    self.services[name] = ServiceLease(name, root)
            records = self._processes()
            by_pid = {int(row['ProcessId']): row for row in records}
            tracked = {}
            for name in ('saw', 'opensearch'):
                path = root / ('run/' + name + '.pid')
                if path.exists():
                    original = path.read_bytes()
                    value = original.decode('ascii').strip()
                    if not value.isdecimal() or not 0 < int(value) <= 0xffffffff:
                        raise DesktopError('process_identity_unverified')
                    tracked[int(value)] = name
                    self.tracking[name] = original
            pg_pid = root / 'data/postgresql/postmaster.pid'
            if pg_pid.exists():
                value = pg_pid.read_text(encoding='utf-8-sig').splitlines()[0]
                if not value.isdecimal():
                    raise DesktopError('process_identity_unverified')
                tracked[int(value)] = 'postgresql'
            groups = {}
            root_prefix = str(root).casefold() + os.sep
            for row in records:
                pid = int(row['ProcessId'])
                image = str(row.get('ExecutablePath') or '')
                command = str(row.get('CommandLine') or '')
                if pid not in tracked and not image.casefold().startswith(root_prefix):
                    continue
                group = self._classify(root, image, command)
                if group is None or (pid in tracked and tracked[pid] != group):
                    raise DesktopError('process_identity_unverified')
                groups[pid] = group
            for pid in tracked:
                if pid in by_pid and pid not in groups:
                    raise DesktopError('process_identity_unverified')
                if pid not in by_pid:
                    # A missing CIM row is not proof that the PID is absent.
                    try:
                        probe = ProcessLease(pid, root / 'does-not-exist.exe')
                    except DesktopError as error:
                        if error.code != 'process_missing':
                            raise
                        self.absent[pid] = tracked[pid]
                    else:
                        probe.close()
                        raise DesktopError('process_identity_unverified')
            # Console hosts are accepted only as direct children of independently
            # identified processes, never as a generally owned executable.
            console_parents = {}
            changed = True
            while changed:
                changed = False
                for row in records:
                    pid, parent = int(row['ProcessId']), int(row['ParentProcessId'])
                    if parent in groups and pid not in groups:
                        group = self._classify(root, row.get('ExecutablePath') or '', row.get('CommandLine') or '')
                        if (group is None and parent not in console_parents and
                                self._is_console_host(row.get('ExecutablePath') or '', row.get('CommandLine') or '')):
                            group = groups[parent]
                            console_parents[pid] = parent
                        if group != groups[parent]:
                            raise DesktopError('process_identity_unverified')
                        groups[pid] = group
                        changed = True
            postgres_parents = {}
            for pid, group in groups.items():
                row = by_pid[pid]
                if group == 'postgresql' and Path(row.get('ExecutablePath') or '') == root / 'pgsql/bin/postgres.exe':
                    tokens = _command_tokens(row.get('CommandLine') or '')
                    if any(value.startswith('--fork') for value in tokens[1:]):
                        parent = int(row['ParentProcessId'])
                        parent_row = by_pid.get(parent, {})
                        parent_tokens = _command_tokens(parent_row.get('CommandLine') or '')
                        if (groups.get(parent) != 'postgresql' or
                                Path(parent_row.get('ExecutablePath') or '') != root / 'pgsql/bin/postgres.exe' or
                                any(value.startswith('--fork') for value in parent_tokens[1:])):
                            raise DesktopError('process_identity_unverified')
                        postgres_parents[pid] = parent
            for pid, group in groups.items():
                row = by_pid[pid]
                try:
                    lease = (ProcessLease(pid, row['ExecutablePath'], terminate=False) if mode == 'service' else
                             ProcessLease(pid, row['ExecutablePath']))
                except DesktopError as error:
                    if error.code == 'process_missing':
                        continue
                    raise
                self.leases.append((pid, int(row['ParentProcessId']), group, lease))
            leased = {pid: (group, lease) for pid, _, group, lease in self.leases}
            for pid, parent in {**console_parents, **postgres_parents}.items():
                if pid not in leased:
                    continue  # The child exited before its handle could be retained.
                if (parent not in leased or leased[parent][0] != leased[pid][0] or
                        leased[parent][1].created_at > leased[pid][1].created_at):
                    raise DesktopError('process_identity_unverified')
            # Re-read metadata while handles retain PID identities; inaccessible/mismatched rows fail.
            fresh = {int(row['ProcessId']): row for row in self._processes()}
            for pid, _, group, lease in self.leases:
                row = fresh.get(pid)
                if row is None:
                    continue  # The retained object may have exited; never reopen by PID.
                if pid in console_parents:
                    if (int(row.get('ParentProcessId', -1)) != console_parents[pid] or
                            not self._is_console_host(row.get('ExecutablePath') or '', row.get('CommandLine') or '')):
                        raise DesktopError('process_identity_unverified')
                elif (self._classify(root, row.get('ExecutablePath') or '', row.get('CommandLine') or '') != group or
                      (pid in postgres_parents and int(row.get('ParentProcessId', -1)) != postgres_parents[pid])):
                    raise DesktopError('process_identity_unverified')
            yield self
        finally:
            for _, _, _, lease in self.leases:
                lease.close()
            self.leases = []
            for lease in self.services.values():
                lease.close()
            self.services = {}

    @staticmethod
    def _same_windows_path(value, expected):
        return (os.path.isabs(value) and
                os.path.normcase(os.path.normpath(value)) == os.path.normcase(os.path.normpath(str(expected))))

    def _is_console_host(self, image, command):
        expected = Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32/conhost.exe'
        tokens = _command_tokens(command)
        if len(tokens) != 2 or not self._same_windows_path(image, expected):
            return False
        native_prefix = chr(92) + '??' + chr(92)
        executable = tokens[0].removeprefix(native_prefix)
        return (self._same_windows_path(executable, expected) and
                re.fullmatch(r'0x[0-9a-fA-F]{1,16}', tokens[1]) is not None and int(tokens[1], 16) > 0)

    def _classify(self, root, image, command):
        executable = Path(image)
        if executable == root / 'pgsql/bin/postgres.exe':
            tokens = _command_tokens(command)
            positions = [index for index, value in enumerate(tokens) if value.startswith('-D')]
            owned = (len(tokens) == 3 and positions == [1] and tokens[1] == '-D' and
                     self._same_windows_path(tokens[2], root / 'data/postgresql'))
            child = not positions and any(value.startswith('--fork') for value in tokens[1:])
            return 'postgresql' if owned or child else None
        if executable == root / 'opensearch-2.19.6/jdk/bin/java.exe':
            options = _command_tokens(command)
            prefix = '-Dopensearch.path.home='
            homes = [value[len(prefix):] for value in options if value.startswith(prefix)]
            return ('opensearch' if len(homes) == 1 and
                    self._same_windows_path(homes[0], root / 'opensearch-2.19.6') else None)
        if executable == root / 'venv/Scripts/python.exe':
            tokens = _command_tokens(command)
            return 'saw' if any(tokens[index:index+3] == ['-m', 'saw.cli', 'serve'] for index in range(len(tokens))) else None
        if executable == Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32/cmd.exe':
            text = command.casefold()
            if str(root / 'opensearch-2.19.6/bin/opensearch.bat').casefold() in text:
                return 'opensearch'
            if str(root / 'venv/Scripts/python.exe').casefold() in text and '-m saw.cli serve' in text:
                return 'saw'
        if executable == root / 'service/saw-service.exe':
            return 'saw'
        if executable == root / 'service/saw-postgresql.exe':
            return 'postgresql'
        if executable == root / 'opensearch-2.19.6/bin/opensearch-service-x64.exe':
            return 'opensearch'
        return None

    def _environment(self, root):
        env = {key: value for key, value in os.environ.items()
               if not key.upper().startswith(('SAW_', 'PG', 'PYTHON', 'JAVA', 'JDK_', 'OPENSEARCH'))
               and key.upper() not in ('CLASSPATH', '_JAVA_OPTIONS')}
        system = Path(os.environ['SystemRoot'])
        jdk = root / 'opensearch-2.19.6/jdk'
        env.update(PATH=str(jdk / 'bin') + ';' + str(system / 'System32') + ';' + str(system),
                   OPENSEARCH_JAVA_HOME=str(jdk), JAVA_HOME=str(jdk),
                   OPENSEARCH_PATH_CONF=str(root / 'opensearch-2.19.6/config'), PYTHONDONTWRITEBYTECODE='1')
        return env

    def _pg(self, root, *arguments, timeout=140):
        result = subprocess.run([str(root / 'pgsql/bin/pg_ctl.exe'), *arguments], cwd=root.parent,
                                env=self._environment(root), stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                creationflags=subprocess.CREATE_NO_WINDOW, timeout=timeout, check=False)
        return result.returncode == 0

    def _forget_tracked(self, root, name):
        from ctypes import wintypes as w
        path = root / ('run/' + name + '.pid')
        if not path.exists():
            return
        allowed = {pid for pid, _, group, lease in self.leases if group == name and
                   lease.kernel.WaitForSingleObject(lease.handle, 0) == 0}
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
        kernel.CreateFileW.restype = w.HANDLE
        kernel.CloseHandle.argtypes = [w.HANDLE]
        kernel.ReadFile.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.c_void_p]
        kernel.GetFileInformationByHandle.argtypes = [w.HANDLE, ctypes.c_void_p]
        kernel.SetFileInformationByHandle.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        handle = kernel.CreateFileW(str(path), 0x80010000, 1, None, 3, 0x00200000, None)
        if handle == w.HANDLE(-1).value:
            raise DesktopError('tracking_changed')
        try:
            class Info(ctypes.Structure):
                _fields_ = [('attributes', w.DWORD), ('created', w.FILETIME), ('accessed', w.FILETIME),
                            ('written', w.FILETIME), ('volume', w.DWORD), ('high', w.DWORD),
                            ('low', w.DWORD), ('links', w.DWORD), ('index_high', w.DWORD), ('index_low', w.DWORD)]
            info, read = Info(), w.DWORD()
            content = ctypes.create_string_buffer(128)
            if (not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)) or
                    info.attributes & 0x410 or info.links != 1 or info.high or info.low > 32 or
                    not kernel.ReadFile(handle, content, 128, ctypes.byref(read), None)):
                raise DesktopError('tracking_changed')
            original = content.raw[:read.value]
            if original != self.tracking.get(name):
                raise DesktopError('tracking_changed')
            value = original.decode('ascii').strip()
            if not value.isdecimal():
                raise DesktopError('tracking_changed')
            pid = int(value)
            if pid not in allowed:
                if self.absent.get(pid) != name:
                    raise DesktopError('tracking_changed')
                try:
                    probe = ProcessLease(pid, root / 'does-not-exist.exe')
                except DesktopError as error:
                    if error.code != 'process_missing':
                        raise DesktopError('tracking_changed') from None
                else:
                    probe.close()
                    raise DesktopError('tracking_changed')
            delete = ctypes.c_ubyte(1)
            if not kernel.SetFileInformationByHandle(handle, 4, ctypes.byref(delete), 1):
                raise DesktopError('tracking_changed')
        finally:
            kernel.CloseHandle(handle)

    def _pg_ready(self, root, cfg):
        result = subprocess.run([str(root / 'pgsql/bin/pg_isready.exe'), '-h', '127.0.0.1',
                                 '-p', str(cfg['postgresPort']), '-t', '3'], cwd=root.parent,
                                env=self._environment(root), stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                creationflags=subprocess.CREATE_NO_WINDOW, timeout=10, check=False)
        return result.returncode == 0
    def _terminate_group(self, group):
        selected = [row for row in self.leases if row[2] == group]
        parents = {row[0]: row[1] for row in selected}
        def depth(row):
            parent, seen = row[1], set()
            while parent in parents and parent not in seen:
                seen.add(parent)
                parent = parents[parent]
            return len(seen)
        for _, _, _, lease in sorted(selected, key=depth, reverse=True):
            lease.stop()

    def stop(self, root, cfg, mode):
        if mode == 'service':
            self.services['saw'].change(False)
        else:
            self._terminate_group('saw')
            self._forget_tracked(root, 'saw')
        search_active = any(group == 'opensearch' for _, _, group, _ in self.leases)
        if search_active or health.check('opensearch', cfg['opensearchPort']):
            if not health.check('flush', cfg['opensearchPort']):
                raise DesktopError('flush_failed')
        if mode == 'service':
            self.services['saw-opensearch'].change(False)
            self.services['saw-postgresql'].change(False)
        else:
            self._terminate_group('opensearch')
            self._forget_tracked(root, 'opensearch')
            if self._pg(root, 'status', '-D', str(root / 'data/postgresql')):
                if not self._pg(root, 'stop', '-D', str(root / 'data/postgresql'), '-m', 'fast', '-w', '-t', '120'):
                    raise DesktopError('stop_failed')

    def _wait(self, check, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if check():
                return
            time.sleep(2)
        raise DesktopError('start_failed')

    def _log_path(self, root, log_name):
        log = root / ('logs/' + log_name)
        backend._path(log, existing=False)
        if log.exists() and (not log.is_file() or log.stat().st_nlink != 1):
            raise DesktopError('unsafe_log_path')
        parents, parent = [], log.parent
        while parent != root:
            if not backend._inside(parent, root):
                raise DesktopError('unsafe_log_path')
            parents.append(parent)
            parent = parent.parent
        current = _current_sid() if os.name == 'nt' else ''
        service_mode = (root / 'service/saw-postgresql.exe').is_file()
        for path in [*parents, log]:
            if path.exists():
                _check_access(path, current, path.relative_to(root), service_mode)
        log.parent.mkdir(parents=True, exist_ok=True)
        backend._path(log, existing=False)
        for path in parents:
            _check_access(path, current, path.relative_to(root), service_mode)
        return log

    def _launch(self, root, command, cwd, log_name, pid_name):
        log = self._log_path(root, log_name)
        with log.open('ab') as output:
            process = subprocess.Popen(command, cwd=cwd, env=self._environment(root), stdin=subprocess.DEVNULL,
                                       stdout=output, stderr=subprocess.STDOUT, close_fds=True,
                                       creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
        run = root / 'run'
        run.mkdir(exist_ok=True)
        temporary = run / (pid_name + '-' + uuid.uuid4().hex + '.writing')
        temporary.write_text(str(process.pid), encoding='ascii')
        os.replace(temporary, run / (pid_name + '.pid'))
        return process

    def start(self, root, cfg, mode):
        if mode == 'service':
            self.services['saw-postgresql'].change(True)
            self._wait(lambda: self._pg_ready(root, cfg), 120)
            self.services['saw-opensearch'].change(True)
        else:
            if any(character in str(root) for character in ('%', '!', '\r', '\n')):
                raise DesktopError('unsupported_shell_path')
            log = self._log_path(root, 'postgresql/postgresql.log')
            if not self._pg(root, 'start', '-D', str(root / 'data/postgresql'), '-l', str(log), '-w', '-t', '120'):
                raise DesktopError('start_failed')
            home = root / 'opensearch-2.19.6'
            cmd = Path(os.environ['SystemRoot']) / 'System32/cmd.exe'
            command = '"' + str(cmd) + '" /d /v:off /s /c ""' + str(home / 'bin/opensearch.bat') + '""'
            self._launch(root, command, home, 'opensearch/desktop-console.log', 'opensearch')
        self._wait(lambda: health.check('opensearch', cfg['opensearchPort']), 240)
        if mode == 'service':
            self.services['saw'].change(True)
        else:
            self._launch(root, [str(root / 'venv/Scripts/python.exe'), '-I', '-B', '-m', 'saw.cli', 'serve',
                                '--host', '127.0.0.1', '--port', str(cfg['port']),
                                '--cert', str(root / 'tls/saw.crt'), '--key', str(root / 'tls/saw.key')],
                         root / 'app', 'saw/desktop-console.log', 'saw')

    def _service_runtime_verified(self, root):
        """Verify SCM process identities and NetworkService postmaster ancestry."""
        opened = {}
        try:
            if set(self.services) != set(SERVICE_PATHS) or any(service.status() != 4 for service in self.services.values()):
                return False
            records = {int(row['ProcessId']): row for row in self._processes()}
            service_pids = {}
            for name, service in self.services.items():
                pid = service.process_id()
                row = records.get(pid)
                if (row is None or not self._same_windows_path(row.get('ExecutablePath') or '', root / SERVICE_PATHS[name]) or
                        not _service_matches(root, {'Name': name, 'PathName': row.get('CommandLine') or ''})):
                    return False
                service_pids[name] = pid
            raw = (root / 'data/postgresql/postmaster.pid').read_text(encoding='utf-8-sig').splitlines()[0]
            if not raw.isdecimal() or not 0 < int(raw) <= 0xffffffff:
                return False
            pg_pid = int(raw)
            pg = records.get(pg_pid)
            if pg is None:
                return False
            pg_args = _command_tokens(pg.get('CommandLine') or '')
            if (not self._same_windows_path(pg.get('ExecutablePath') or '', root / 'pgsql/bin/postgres.exe') or
                    len(pg_args) != 3 or pg_args[1] != '-D' or
                    not self._same_windows_path(pg_args[2], root / 'data/postgresql') or
                    int(pg.get('ParentProcessId', 0)) != service_pids['saw-postgresql']):
                return False
            for pid in {*service_pids.values(), pg_pid}:
                opened[pid] = ProcessLease(pid, records[pid]['ExecutablePath'], terminate=False)
            if opened[service_pids['saw-postgresql']].created_at > opened[pg_pid].created_at:
                return False
            fresh = {int(row['ProcessId']): row for row in self._processes()}
            for pid, lease in opened.items():
                if lease.kernel.WaitForSingleObject(lease.handle, 0) != 258:
                    return False
                row = fresh.get(pid)
                if row is None or any(row.get(field) != records[pid].get(field)
                                      for field in ('ExecutablePath', 'CommandLine', 'ParentProcessId')):
                    return False
            return all(service.status() == 4 and service.process_id() == service_pids[name]
                       for name, service in self.services.items())
        except Exception:
            return False
        finally:
            for lease in opened.values():
                lease.close()

    def healthy(self, root, cfg, host):
        self._wait(lambda: health.check('api', cfg['port'], root / 'tls/saw.crt', host), 180)
        postgres_owned = (self._service_runtime_verified(root) if self.services else
                          self._pg(root, 'status', '-D', str(root / 'data/postgresql')))
        return (postgres_owned and self._pg_ready(root, cfg) and
                health.check('opensearch', cfg['opensearchPort']) and
                health.check('api', cfg['port'], root / 'tls/saw.crt', host))

class QuietParser(argparse.ArgumentParser):
    def error(self, message):
        raise DesktopError('invalid_arguments')


def main(argv=None):
    parser = QuietParser(add_help=False, allow_abbrev=False)
    parser.add_argument('action', choices=('inspect', 'apply', 'restore', 'start'))
    parser.add_argument('--install-root', required=True, type=Path)
    parser.add_argument('--bundle-dir', required=True, type=Path)
    parser.add_argument('--state-dir', required=True, type=Path)
    parser.add_argument('--baseline-bundle-dir', type=Path)
    parser.add_argument('--recovery-point', type=Path)
    parser.add_argument('--maintenance-confirmed', action='store_true')
    parser.add_argument('--confirm-point-in-time-recovery', action='store_true')
    try:
        args = parser.parse_args(argv)
        result = run(args.action, args.install_root, args.bundle_dir, args.state_dir,
                     baseline_dir=args.baseline_bundle_dir, recovery_point=args.recovery_point,
                     maintenance_confirmed=args.maintenance_confirmed,
                     confirm=args.confirm_point_in_time_recovery)
        print(json.dumps(result, ensure_ascii=True))
        return 0 if result['status'] in ('ready', 'completed') else 1
    except Exception:
        print('Desktop update refused; preserve all installation and recovery directories.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
