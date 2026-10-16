# Offline release refresh and cold recovery design — 2026-10-17

User intent: carry the implemented SOC workbench into an air-gapped LTSC2019 x64 installation and make updates recoverable. Latest source already contains behavior analysis, offline content lifecycle and schema0014. Original Claude checkout and operational bank data are out of scope.

Scope: rebuild complete model-free media using the existing pinned runtime closure; add a conservative stopped-install application update with a verified cold recovery point. Keep PostgreSQL16.15/OpenSearch2.19.6/Python3.12.10/llama runtime unchanged. Reject different dependencies/runtime pins, external mutable storage, reparse paths, active processes/ports and insufficient disk rather than perform an unsafe partial update. Credentials remain private.

Recovery: app-only downgrade across schema0011→0014 is not supported. Before update, copy the complete stopped installation to a protected sibling recovery point, excluding no mutable state. Hash-check the copy. On explicit restore, preserve the current installation as a separate retained directory and restore the complete pre-update installation at its original absolute path. No automatic deletion, database downgrade or operational data discard. New records after update remain in the retained directory and require deliberate reconciliation.

Execution: existing user authorization permits routine design/implementation and local synthetic user-process tests. No administrator installation, service registration, firewall change or operational model/data activation. Service mode support is code/preflight only until separately approved native testing.

Acceptance: fresh full server/UI checks; real bundle install using bundled Python/wheels/PG/OpenSearch/TLS; synthetic log/PCAP + new behavior flow; full restart persistence; old schema0011 installation→new source0014→cold restore0011→reapply0014; integrity and refusal paths; actual ZIP per-file digest and private GitHub publication. Win11 results remain separate from clean LTSC acceptance. Physical internet isolation and shared16GB load are not inferred.

Native execution findings (2026-10-17): exact DACL comparison exposed loss of AUTO_INHERITED under SetFileSecurity. Preserve the original control state by an explicit inheritance request and verify the exact resulting DACL before any private content is written. Do not normalize away permission differences.

A separate P1 was confirmed: a custom install root could inherit broad local-user access, including app/var/secret.key and executable code. Fresh installation must start in a new/empty validated directory with an exact protected root DACL before children are created. Preserve PostgreSQL NetworkService access only to its necessary runtime/data/log/service paths. Existing installations are not silently repermissioned: plan/apply require trusted ownership and allowed DACL principals before reading private state. Application staging copies public content into existing approved ACLs or approved parent inheritance; it must never import broader media ACLs. Cold recovery keeps the original approved DACLs. Owner/SACL cloning remains outside the supported guarantee.


## Native recovery path limit correction
Actual candidate4 restore failed before root switch: long staging basename caused WinError206 at a 251-unit directory. Use compact random sibling names and conservative UTF-16 path preflight before copy/rename, including retained current data. Do not change Windows long-path policy. Native regression, independent review, candidate5 restore/reapply and whole-suite verification are required. Fresh installer/engine/UI/runtime candidate4-to5 payload is byte-identical; only offline_update.py changed.
