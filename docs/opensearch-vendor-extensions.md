# OpenSearch vendor extension mapping

New indices retain arbitrary vendor JSON objects in `_source` with their original types. Generation canonical hashes and strict malformed-value checks are unchanged. A dynamic template maps only unknown top-level `ext.<namespace>` objects to `flat_object`, so mixed numeric/string leaves do not create competing leaf mappings. Existing indices, including published and retained generation indices, are not remapped.

The following fixed namespaces retain ordinary typed object mappings:

| Origin | Namespaces | Existing dependencies |
|---|---|---|
| Built-in parsers | `apache`, `cloudflare`, `csv`, `iis`, `json`, `kv`, `ndr`, `nginx`, `suricata`, `syslog`, `waf`, `zeek` | Parser products in `saw/parsers`; `ext.zeek.duration` numeric range, Zeek service/category aggregations, Suricata signature ID grouping, syslog detectors |
| Producer metadata | `observation`, `saw_observation`, `device_observation`, `connector` | Scoped network/context filters, observed counters, device metrics, parser observations, connector source linkage |
| Supported mock connector | `fw`, `ips`, `vpn` | Firewall action, IPS signature/action, VPN outcome |

Analyst-defined parsers emit `ext.u_<slug>` (`saw/parsers/custom.py`); that reserved prefix retains ordinary typed mapping as well. These are mapping compatibility rules, not permission or context-trust rules. The fixture test checks that every actual built-in parser product remains in the fixed list. Add future typed producer/parser namespaces deliberately with coverage, rather than relying on their first input value.

The unknown-object template matches exactly one path component under `ext`, not descendants of known namespaces. Known mappings therefore retain nested numeric/boolean fields and the existing event timestamp/date statistics. Mixed or incompatible values in a known typed field still fail strict generation writes; arbitrary vendor objects belong in a distinct unrecognized namespace. Scalar values directly under `ext` are outside this object-namespace rule.

Unknown flattened vendor fields support exact lookup, including dotted paths, and canonical source retrieval. They do **not** provide numeric comparison/sorting, numeric subfield statistics or dotted-subfield aggregations. Their values must not be presented as typed numeric measures. Queries requiring those semantics need an explicit reviewed typed mapping/normalization contract. No canonical payload stringification, array homogenization, field dropping or malformed-value suppression is performed.

Official OpenSearch 2.19 references: [flat_object](https://docs.opensearch.org/2.19/field-types/supported-field-types/flat-object/) describes exact dot-path queries and numeric/aggregation limits; [dynamic templates](https://docs.opensearch.org/2.19/field-types/#dynamic-templates) documents object type matching and regex path matching. Documentation describes some subfield-filter limitations inconsistently with its supported exact-query examples; native regression tests establish the exact term-query behavior required here rather than promising all arbitrary subfield operations.
