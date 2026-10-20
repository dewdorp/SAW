"""Inherited source authority survives a new run without the original rule pin."""
from saw.analysis_runs import service as history
from saw.core.application import identity
from saw.reports import service as reports
from saw.storage.db import session_scope
from saw.storage.models import InvestigationMember, User
from tests.api.test_derived_finding_access import generated
from tests.conftest import Api, make_user


def test_retained_derived_snapshot_requires_its_source_without_current_pin(analyst, manager, app):
    reader_id = make_user("snapshot-target-reader", ["analyst"])
    with session_scope() as s:
        source, target, finding, _old = generated(s)
        s.add(InvestigationMember(investigation_id=target.id, user_id=reader_id, access="read"))
        new = history.start(s, target.id)
        history.capture_findings(s, new, [finding])
        history.finish(s, new)
        owner = identity.principal_of(s.get(User, target.owner_id))
        report = reports.create(s, owner, target.id, analysis_run_id=new.id)
        target_id, run_id, report_id = target.id, new.id, report.id
    reader = Api(app, "snapshot-target-reader")
    assert reader.get(f"/investigations/{target_id}/analysis-runs/{run_id}").status_code in {403, 404}
    assert reader.get(f"/investigations/{target_id}/report-versions/{report_id}").status_code in {403, 404}


def test_unreadable_derived_input_cannot_publish_in_new_run(analyst, manager):
    import pytest
    from saw.core.application.investigations import Forbidden
    reader_id = make_user("snapshot-target-writer", ["analyst"])
    with session_scope() as s:
        _source, target, finding, _old = generated(s)
        s.add(InvestigationMember(investigation_id=target.id, user_id=reader_id, access="editor"))
        new = history.start(s, target.id)
        new.created_by = reader_id
        with pytest.raises(Forbidden):
            history.capture_findings(s, new, [finding])
