# OpenSearch vendor extension mapping

New indices retain arbitrary vendor JSON objects in `_source` with their original types. Generation canonical hashes and strict malformed-value checks are unchanged. A dynamic template maps only unknown top-level `ext.<namespace>` objects to `flat_object`, so mixed numeric/string leaves do not create competing leaf mappings. Existing indices, including published and retained generation indices, are not remapped.

The following fixed namespaces retain ordinary typed object mappings:

| Origin | Namespaces | Existing dependencies |
|---|---|---|
| Built-in parsers | `apache`, `cloudflare`, `csv`, `iis`, `json`, `kv`, `ndr`, `nginx`, `security_csv`, `suricata`, `syslog`, `waf`, `zeek` | Parser products in `saw/parsers`; `ext.zeek.duration` numeric range, Zeek service/category aggregations, Suricata signature ID grouping, syslog detectors |
| Producer metadata | `observation`, `saw_observation`, `device_observation`, `connector` | Scoped network/context filters, observed counters, device metrics, parser observations, connector source linkage |
| Supported mock connector | `fw`, `ips`, `vpn` | Firewall action, IPS signature/action, VPN outcome |

Analyst-defined parsers emit `ext.u_<slug>` (`saw/parsers/custom.py`); that reserved prefix retains ordinary typed mapping as well. These are mapping compatibility rules, not permission or context-trust rules. The fixture test checks that every actual built-in parser product remains in the fixed list. Add future typed producer/parser namespaces deliberately with coverage, rather than relying on their first input value.

The unknown-object template matches exactly one path component under `ext`, not descendants of known namespaces. Known mappings therefore retain nested numeric/boolean fields and the existing event timestamp/date statistics. Mixed or incompatible values in a known typed field still fail strict generation writes; arbitrary vendor objects belong in a distinct unrecognized namespace. Scalar values directly under `ext` are outside this object-namespace rule.

Unknown flattened vendor fields support exact lookup, including dotted paths, and canonical source retrieval. They do **not** provide numeric comparison/sorting, numeric subfield statistics or dotted-subfield aggregations. Their values must not be presented as typed numeric measures. Queries requiring those semantics need an explicit reviewed typed mapping/normalization contract. No canonical payload stringification, array homogenization, field dropping or malformed-value suppression is performed.

Official OpenSearch 2.19 references: [flat_object](https://docs.opensearch.org/2.19/field-types/supported-field-types/flat-object/) describes exact dot-path queries and numeric/aggregation limits; [dynamic templates](https://docs.opensearch.org/2.19/field-types/#dynamic-templates) documents object type matching and regex path matching. Documentation describes some subfield-filter limitations inconsistently with its supported exact-query examples; native regression tests establish the exact term-query behavior required here rather than promising all arbitrary subfield operations.


The dedicated `security_csv` adapters recognize the complete exact FW/NDR header signatures with at most 199 source columns. Extra column names must be nonempty after whitespace checking and contain no dot; these flat-name constraints prevent a source field such as `csv_format.x` from colliding with typed metadata paths. Literal source columns named `csv_format` or `source_columns` are retained inside a consistently object-shaped `source_columns` dictionary. Other supported flat extras keep their original values directly under the namespace.

Unsupported headers fail closed when a dedicated adapter is explicitly selected. Automatic detection may select the existing generic CSV parser instead: inspect the selected parser before relying on dedicated-format readiness. The original evidence/raw references are preserved; no unsupported source values are silently dropped by these adapters. Korean source keys remain available in canonical source retrieval; the current structured Query Model admits ASCII field paths such as `ext.security_csv.csv_format`, and this mapping change does not promise Korean-named structured filters.
