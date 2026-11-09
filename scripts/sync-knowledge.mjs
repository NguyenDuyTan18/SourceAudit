import { createRequire } from 'node:module';
import { mkdir, writeFile, rename } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createHash } from 'node:crypto';
const root = fileURLToPath(new URL('../', import.meta.url));
const require = createRequire(path.join(root, 'package.json'));
const { XMLParser } = require('fast-xml-parser');
const { unzipSync } = require('fflate');
const output = path.join(root, 'data');
await mkdir(output, { recursive: true });
const sources = []; const errors = []; const advisories = new Map();
async function download(url, maxBytes = 30000000) {
  const response = await fetch(url, { headers: { 'User-Agent': 'SourceAudit-Local-Knowledge-Builder/1.0', Accept: url.includes('api.github') ? 'application/vnd.github+json' : '*/*' }, signal: AbortSignal.timeout(45000) });
  if (!response.ok) throw new Error(`HTTP ${response.status} ${url}`);
  const chunks = []; let size = 0;
  for await (const chunk of response.body) { size += chunk.length; if (size > maxBytes) throw new Error('Download limit'); chunks.push(chunk); }
  const buffer = Buffer.concat(chunks);
  sources.push({ url, retrievedAt: new Date().toISOString(), sha256: createHash('sha256').update(buffer).digest('hex'), bytes: size });
  return { buffer, next: response.headers.get('link')?.match(/<([^>]+)>; rel="next"/)?.[1] };
}
const list = (value) => value === undefined ? [] : Array.isArray(value) ? value : [value];
function text(value) { if (value == null) return ''; if (typeof value !== 'object') return String(value); return Object.entries(value).filter(([key]) => !['ID', 'Name', 'Nature', 'Ordinal', 'View_ID'].includes(key)).flatMap(([, item]) => list(item).map(text)).join(' ').replace(/\s+/g, ' ').trim(); }

const cweResult = await download('https://cwe.mitre.org/data/xml/cwec_latest.xml.zip');
const cweZip = unzipSync(cweResult.buffer);
const xml = Buffer.from(Object.values(cweZip)[0]).toString('utf8');
const parsed = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '', textNodeName: 'text', processEntities: false }).parse(xml).Weakness_Catalog;
const weaknesses = list(parsed.Weaknesses.Weakness).map((entry) => ({ id: `CWE-${entry.ID}`, kind: 'cwe', name: entry.Name, cwes: [`CWE-${entry.ID}`], abstraction: entry.Abstraction, status: entry.Status, description: text(entry.Description).slice(0, 2000), mitigations: list(entry.Potential_Mitigations?.Mitigation).map((m) => text(m.Description).slice(0, 1000)).filter(Boolean).slice(0, 5), platforms: text(entry.Applicable_Platforms).slice(0, 500), consequences: text(entry.Common_Consequences).slice(0, 800), references: [`https://cwe.mitre.org/data/definitions/${entry.ID}.html`] }));
console.log(`CWE: ${weaknesses.length}, version ${parsed.Version}`);

const wstgResult = await download('https://codeload.github.com/OWASP/wstg/zip/refs/tags/v4.2');
const wstgZip = unzipSync(wstgResult.buffer);
const wstg = [];
for (const [filename, bytes] of Object.entries(wstgZip)) {
  if (!filename.includes('/document/4-Web_Application_Security_Testing/') || !filename.endsWith('.md') || filename.endsWith('README.md')) continue;
  const body = Buffer.from(bytes).toString('utf8');
  const id = body.match(/\bWSTG-[A-Z]+-\d+\b/)?.[0];
  if (!id || wstg.some((entry) => entry.id === id)) continue;
  const slug = filename.split('/document/')[1].replace(/\.md$/, '');
  const section = (heading) => body.match(new RegExp(`## ${heading}\\s+([\\s\\S]*?)(?=\\n## |$)`, 'i'))?.[1] || '';
  const clean = (value) => value.replace(/```[\s\S]*?```/g, '').replace(/!\[[^\]]*\]\([^)]*\)/g, '').replace(/\[([^\]]+)\]\([^)]*\)/g, '$1').replace(/[#*_`>|]/g, '').replace(/\s+/g, ' ').trim();
  wstg.push({ id, kind: 'owasp', name: body.match(/^#\s+(.+)$/m)?.[1] || id, cwes: [...new Set([...body.matchAll(/\bCWE[- ](\d+)\b/g)].map((m) => `CWE-${m[1]}`))], description: clean(section('Summary')).slice(0, 1600), objectives: clean(section('Test Objectives')).slice(0, 1600), references: [`https://owasp.org/www-project-web-security-testing-guide/v42/${slug}`] });
}
console.log(`OWASP WSTG v4.2: ${wstg.length}`);
const configs = [['npm', 3], ['pip', 2], ['composer', 1], ['maven', 1], ['nuget', 1], ['rubygems', 1], ['go', 1]];
function ingest(records) {
  for (const item of records) {
    if (item.withdrawn_at || item.type !== 'reviewed') continue;
    advisories.set(item.ghsa_id, { id: item.ghsa_id, kind: 'advisory', cve: item.cve_id, name: item.summary, severity: item.severity, description: item.description?.slice(0, 5000) || '', cwes: (item.cwes || []).map((c) => c.cwe_id), publishedAt: item.published_at, updatedAt: item.updated_at, references: [item.html_url, ...item.references.filter((ref) => /^https:\/\//.test(ref)).slice(0, 8)], vulnerabilities: item.vulnerabilities.map((v) => ({ ecosystem: v.package.ecosystem, name: v.package.name, range: v.vulnerable_version_range, fixed: v.first_patched_version })) });
  }
}
for (const [ecosystem, pages] of configs) {
  let url = `https://api.github.com/advisories?type=reviewed&ecosystem=${ecosystem}&per_page=100&sort=updated&direction=desc`;
  for (let page = 0; page < pages && url; page++) {
    try { const result = await download(url); ingest(JSON.parse(result.buffer)); url = result.next; }
    catch (error) { errors.push(String(error.message)); break; }
  }
  console.log(`Advisories after ${ecosystem}: ${advisories.size}`);
}
for (const cve of ['CVE-2021-23337', 'CVE-2022-29078', 'CVE-2022-23529', 'CVE-2025-29927', 'CVE-2024-34069']) {
  try { ingest(JSON.parse((await download(`https://api.github.com/advisories?cve_id=${cve}`)).buffer)); } catch (error) { errors.push(String(error.message)); }
}
const corpus = { schemaVersion: 1, builtAt: new Date().toISOString(), cweVersion: parsed.Version, wstgVersion: '4.2', selection: 'Complete published CWE weakness list; all WSTG v4.2 test IDs; bounded recent GitHub-reviewed advisory pages for seven ecosystems plus five reference CVEs. Advisory sample is not complete.', sources, errors, weaknesses, wstg, advisories: [...advisories.values()] };
if (advisories.size < 100) throw new Error('Insufficient advisory data; keeping the existing corpus.');
await writeFile(path.join(output, 'corpus.pending.json'), JSON.stringify(corpus) + '\n');
await rename(path.join(output, 'corpus.pending.json'), path.join(output, 'corpus.json'));
await writeFile(path.join(output, 'manifest.json'), JSON.stringify({ ...corpus, weaknesses: weaknesses.length, wstg: wstg.length, advisories: advisories.size }, null, 2));
const licenses = ['CWE data: Copyright The MITRE Corporation. CWE is a trademark of The MITRE Corporation. Source: https://cwe.mitre.org/about/termsofuse.html', 'CWE license: non-exclusive, royalty-free license for research, development and commercial purposes, on condition that MITRE copyright designation and license are reproduced. See bundled upstream CWE-license.html for the full terms.'];
for (const [filename, url] of [['CWE-license.html', 'https://cwe.mitre.org/about/termsofuse.html'], ['GHSA-LICENSE.md', 'https://raw.githubusercontent.com/github/advisory-database/main/LICENSE.md']]) {
  try { await writeFile(path.join(output, filename), (await download(url)).buffer); } catch (error) { console.log('License fetch:', error.message); }
}
const wstgLicense = Object.entries(wstgZip).find(([name]) => /(?:LICENSE|COPYING)(?:\.md|\.txt)?$/i.test(name));
if (wstgLicense) await writeFile(path.join(output, 'WSTG-LICENSE.txt'), wstgLicense[1]);
await writeFile(path.join(output, 'NOTICE.md'), '# Dataset attribution\n\n' + licenses.join('\n\n') + '\n\nOWASP WSTG v4.2: OWASP Foundation and contributors, CC BY-SA 4.0. Excerpts normalized/truncated; source URLs retained.\n\nGitHub Advisory Database: GitHub and contributors, CC-BY 4.0, original advisory IDs/URLs retained. Advisory descriptions normalized/truncated.\n');
console.log(JSON.stringify({ weaknesses: weaknesses.length, wstg: wstg.length, advisories: advisories.size, errors }));
