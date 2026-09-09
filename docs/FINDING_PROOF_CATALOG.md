# Finding Proof Catalog (STEP 59)

Vulnerability emissions must document baseline → mutation → proof → negative control.

| check_id | baseline | mutation | proof | negative control | evidence stored |
| -------- | -------- | -------- | ----- | ---------------- | --------------- |
| injection.html.reflected | clean GET | inject markup | markup unescaped in body | encoded reflection | request/response snippets redacted |
| browser.dom_xss | page load | hash/query sink | runtime canary attribute | no execution | canary id only |
| idor.cross_account | owner read | peer read same object | peer sees owner private fields | public object filter | semantic fingerprint, no secrets |
| authz.matrix.allow | expected deny | subject/action | observed allow | role mismatch skip | subject/resource ids |
| parameter.ssti | benign param | template payload | evaluated marker | inert reflection | marker only |
| parameter.crlf | normal header | CRLF inject | response header split | ignored param | header names |
| server.path_traversal | normal file | `../` sequence | known file marker | missing file | path pattern |
| server.ssrf.callback | blocked URL | callback host | callback hit | DNS fail | host only |
| active.open_redirect | same-origin | external URL | 3xx Location external | non-redirect param | location host |
| server.auth_sqli.bypass | bad creds | SQLi body | auth success signal | invalid still denied | status/body fingerprint |
| websocket.cswsh.accepted | same-origin WS | foreign Origin | connect succeeds | connect fail | origin value |
| workflow.authz.write | A creates | B mutates | B write succeeds | cleanup | object id fingerprint |
| workflow.stored_xss | empty note | canary store | canary in render | deleted | canary token |
| cors.misconfig | benign Origin | evil Origin | ACAO reflects evil | public CDN allowlist | origin value |
| graphql.introspection | blocked | __schema query | schema fields leak | disabled introspect | type names |
| upload.cross_account | A uploads | B fetches | B reads A object | private ACL deny | object id |
| ssrf | blocked URL | callback host | callback hit | DNS fail | host only |
| crlf | normal header | CRLF inject | response header split | ignored param | header names |
| traversal | normal file | `../` sequence | known file marker | missing file | path pattern |
| redirect | same-origin | external URL | 3xx Location external | non-redirect | location host |

Rule: regex / status / header absence / source smell alone → Exposure / Hardening / Observation, never Vulnerability.
