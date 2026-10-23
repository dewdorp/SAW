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

ROUTERS = [followups_router, analysis_runs_router, source_context_router, behavior_router, content_packages_router, guidance.router, golden.router, auth.router, admin.router, admin_data.router, investigations.router, analyze.router, evidence.router, workbench.router,
           cases.router, attack.router, network.router, forensics.router, knowledge.router, connectors.router, ai.router, hunting.router, detection.router,
           parser_library.router, provenance.router, briefing.router, checks.router, reviews.router, local_models.router]
