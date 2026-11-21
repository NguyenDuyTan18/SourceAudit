# Offline recognition context

`research.json` adds six locally searchable research summaries with bibliographic details, primary links, methodological limitations and concrete applications to SrcAudit. The knowledge library displays them under **Nghiên cứu**. Research entries provide evaluation context and do not participate in scan matching.

`references.json` adds seven official technical references under **Tài liệu kỹ thuật**. Each entry records how to use the source in review, release, or evaluation. These records do not change rule or dependency matching.

Extension refreshed on 2026-11-21. The offline library contains 6,116 records: 984 CWE, 97 WSTG, 345 ASVS, 33 API Security entries, 2,867 unique reviewed advisories and 1,790 CISA KEV entries. The runtime merges `corpus.json` and `extensions.json` by advisory ID and prefers the newer record. `extensions-manifest.json` records source URLs, retrieval times, SHA-256 hashes and counts. The new broad npm, PyPI and Composer sample adds package names, affected ranges, fixed versions, CWE and canonical advisory links. CWE, standards and KEV provide review context. Dependency findings require a match against a locally resolved version.

Snapshot 2026-11-05: 984 CWE weaknesses v5.0, 97 OWASP WSTG scenarios v4.2 and 936 GitHub-reviewed advisories; 2017 context records. Curated descriptions are not executable detectors.

corpus.json contains normalized/truncated descriptions, mitigation context, objectives, affected ranges and references. manifest.json records source URLs, download dates, SHA-256 of original downloads, selection and counts. No project source or private dependency inventory was sent during collection.

CWE data © The MITRE Corporation. CWE is a trademark of The MITRE Corporation. Terms bundled in CWE-license.html. OWASP WSTG © OWASP Foundation and contributors, CC BY-SA 4.0; terms bundled in WSTG-LICENSE.txt. GitHub Advisory Database © GitHub and contributors, CC-BY 4.0; terms bundled in GHSA-LICENSE.md. Normalization/truncation is an adaptation; original IDs and URLs remain. No endorsement is implied.

Advisory subset: up to 3 recent pages for npm, 2 for pip, 1 each for Composer/Maven/NuGet/RubyGems/Go, plus five reference CVEs. Withdrawn/non-reviewed records excluded, GHSA IDs deduplicated. This is not a complete CVE database or a finding of exploitability.
