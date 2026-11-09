const clean = (value) => String(value || '').replace(/```[\s\S]*?```/g, '').replace(/!\[[^\]]*\]\([^)]*\)/g, '').replace(/\[([^\]]+)\]\([^)]*\)/g, '$1').replace(/[#*_`>|]/g, '').replace(/\s+/g, ' ').trim();
const cwes = (value) => [...new Set([...String(value).matchAll(/\bCWE[- ](\d+)\b/g)].map((match) => 'CWE-' + match[1]))];
export function parseAsvs(data) {
  if (!Array.isArray(data?.requirements)) throw new Error('Unsupported ASVS schema');
  return data.requirements.filter((entry) => /^V\d+\.\d+\.\d+$/.test(entry.req_id) && typeof entry.req_description === 'string').map((entry) => ({
    id: 'ASVS-v5.0.0-' + entry.req_id.slice(1), kind: 'asvs', name: `${entry.req_id} ${entry.section_name}`, description: clean(entry.req_description), level: entry.L, chapter: entry.chapter_name,
    cwes: cwes(entry.req_description), reviewSteps: [clean(entry.req_description)], references: ['https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json'], role: 'verification-requirement-not-detector'
  }));
}
export function parseApiRisk(body, filename, commit) {
  const heading = body.match(/^#\s+(API\d+:2023)\s+(.+)$/m);
  if (!heading) return [];
  const [, id, title] = heading;
  const references = [`https://github.com/OWASP/API-Security/blob/${commit}/editions/2023/en/${filename}`];
  const prevent = body.match(/## How To Prevent\s+([\s\S]*?)(?=\n## |$)/i)?.[1] || '';
  const parent = { id, kind: 'api', name: title, description: clean(body.slice(0, body.indexOf('## Example Attack Scenarios') > 0 ? body.indexOf('## Example Attack Scenarios') : 6000)).slice(0, 2000), cwes: cwes(body), reviewSteps: prevent ? [clean(prevent).slice(0, 2500)] : ['Đối chiếu mô hình phân quyền, xác thực và nghiệp vụ trước khi đánh giá.'], references, role: 'manual-test-context' };
  const entries = [parent];
  for (const match of body.matchAll(/###\s+Scenario\s*#?\s*(\d+)\s*\n([\s\S]*?)(?=\n### |\n## |$)/gi)) entries.push({ ...parent, id: id + '-SCENARIO-' + match[1], name: `${title} — Scenario ${match[1]}`, description: clean(match[2]).slice(0, 2500), parentId: id });
  return entries;
}
export function parseKev(data) {
  if (!Array.isArray(data?.vulnerabilities)) throw new Error('Unsupported KEV schema');
  return data.vulnerabilities.filter((entry) => /^CVE-\d{4}-\d{4,}$/.test(entry.cveID)).map((entry) => ({
    id: 'KEV-' + entry.cveID, cve: entry.cveID, kind: 'kev', name: entry.vulnerabilityName, description: entry.shortDescription, vendor: entry.vendorProject, product: entry.product,
    dateAdded: entry.dateAdded, cwes: Array.isArray(entry.cwes) ? entry.cwes.filter((cwe) => /^CWE-\d+$/.test(cwe)) : [], reviewSteps: [entry.requiredAction || 'Đọc hướng dẫn giảm thiểu của nhà cung cấp.'],
    references: ['https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'https://nvd.nist.gov/vuln/detail/' + entry.cveID], role: 'public-exploitation-history-not-local-compromise'
  }));
}
