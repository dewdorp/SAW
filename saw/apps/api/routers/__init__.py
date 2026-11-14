from saw.apps.api.routers import (
    admin,
    admin_data,
    ai,
    analyze,
    attack,
    auth,
    briefing,
    cases,
    checks,
    connectors,
    detection,
    evidence,
    forensics,
    guidance,
    golden,
    hunting,
    investigations,
    local_models,
    knowledge,
    network,
    parser_library,
    provenance,
    reviews,
    workbench,
)

from saw.content_packages.router import router as content_packages_router

from saw.behavior.router import router as behavior_router

from saw.analysis_runs.router import router as analysis_runs_router
from saw.source_context.router import router as source_context_router

from saw.followups.router import router as followups_router

from saw.internal_kb.router import router as internal_kb_router

from saw.apps.api.routers.system import router as system_router
from saw.flows.router import router as flows_router
from saw.assets.router import router as assets_router
from saw.hunts.router import router as hunts_router
from saw.scenarios.router import router as scenarios_router
from saw.question_presets.router import router as question_presets_router

ROUTERS = [system_router, assets_router, hunts_router, scenarios_router, flows_router, question_presets_router, internal_kb_router, followups_router, analysis_runs_router, source_context_router, behavior_router, content_packages_router, guidance.router, golden.router, auth.router, admin.router, admin_data.router, investigations.router, analyze.router, evidence.router, workbench.router,
           cases.router, attack.router, network.router, forensics.router, knowledge.router, connectors.router, ai.router, hunting.router, detection.router,
           parser_library.router, provenance.router, briefing.router, checks.router, reviews.router, local_models.router]
