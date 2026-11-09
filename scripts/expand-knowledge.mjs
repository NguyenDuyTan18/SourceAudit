import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { parseAsvs, parseApiRisk, parseKev } from '../src/scenario-import.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const output = path.join(root, 'data');
await mkdir(output, { recursive: true });
const sources = []; const errors = [];
async function download(url, limit = 30000000) {
  const response = await fetch(url, { headers: { 'User-Agent': 'SrcAuditPublicScenarioCollector/1.0', Accept: url.startsWith('https://api.github.com/') ? 'application/vnd.github+json' : '*/*' }, signal: AbortSignal.timeout(40000) });
  if (!response.ok) throw new Error(`HTTP ${response.status} ${url}`);
  const chunks = []; let bytes = 0;
  for await (const chunk of response.body) { bytes += chunk.length; if (bytes > limit) throw new Error('Source exceeds collection limit'); chunks.push(chunk); }
  const buffer = Buffer.concat(chunks);
  sources.push({ url, sha256: createHash('sha256').update(buffer).digest('hex'), bytes, retrievedAt: new Date().toISOString() });
  return { buffer, next: response.headers.get('link')?.match(/<([^>]+)>; rel="next"/)?.[1] };
}
const asvsUrl = 'https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0_release/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json';
const asvs = parseAsvs(JSON.parse((await download(asvsUrl)).buffer));
console.log(`ASVS v5.0.0: ${asvs.length}`);
const apiCommit = '33cea37b2ffde3e2e62f6b5d79a029a22a846633';
const api = [];
const apiFiles = ['0xa1-broken-object-level-authorization.md', '0xa2-broken-authentication.md', '0xa3-broken-object-property-level-authorization.md', '0xa4-unrestricted-resource-consumption.md', '0xa5-broken-function-level-authorization.md', '0xa6-unrestricted-access-to-sensitive-business-flows.md', '0xa7-server-side-request-forgery.md', '0xa8-security-misconfiguration.md', '0xa9-improper-inventory-management.md', '0xaa-unsafe-consumption-of-apis.md'];
for (const filename of apiFiles) {
  const content = (await download(`https://raw.githubusercontent.com/OWASP/API-Security/${apiCommit}/editions/2023/en/${filename}`)).buffer;
  api.push(...parseApiRisk(content.toString('utf8'), filename, apiCommit));
}
console.log(`API Security 2023 risks and scenarios: ${api.length}`);
const kevSource = JSON.parse((await download('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')).buffer);
const kev = parseKev(kevSource);
console.log(`CISA KEV ${kevSource.catalogVersion}: ${kev.length}`);
let previous = {};
try { previous = JSON.parse(await readFile(path.join(output, 'extensions.json'), 'utf8')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
const advisoryMap = new Map((previous.advisories || []).map((record) => [record.id, record]));
const packageGroups = [
  ['npm', 3, ['next', 'lodash', 'axios', 'express', 'ejs', 'jsonwebtoken', 'dompurify', 'jquery', 'handlebars', 'qs', 'multer', 'vite', 'webpack', 'path-to-regexp', 'react-router', 'fastify', 'pug', 'underscore', 'sanitize-html']],
  ['pip', 3, ['django', 'flask', 'werkzeug', 'requests', 'urllib3', 'jinja2', 'pyyaml', 'starlette', 'fastapi', 'aiohttp', 'pillow', 'cryptography', 'python-jose', 'pyjwt', 'sqlparse']],
  ['composer', 2, ['laravel/framework', 'symfony/http-foundation', 'symfony/http-kernel', 'twig/twig', 'guzzlehttp/guzzle', 'league/commonmark']],
  ['maven', 1, ['org.springframework:spring-web', 'org.springframework:spring-webmvc', 'org.apache.tomcat.embed:tomcat-embed-core', 'com.fasterxml.jackson.core:jackson-databind']],
  ['nuget', 1, ['Microsoft.AspNetCore.App', 'System.Text.Json', 'Newtonsoft.Json']],
  ['rubygems', 1, ['rails', 'actionpack', 'rack', 'nokogiri']]
];
for (const [ecosystem, pages, names] of packageGroups) {
  const query = new URLSearchParams({ type: 'reviewed', ecosystem, per_page: '100', sort: 'updated', direction: 'desc' });
  for (const name of names) query.append('affects[]', name);
  let url = 'https://api.github.com/advisories?' + query;
  for (let page = 0; page < pages && url; page++) {
    try {
      const response = await download(url);
      for (const record of JSON.parse(response.buffer)) {
        if (record.withdrawn_at || record.type !== 'reviewed') { if (record.withdrawn_at) advisoryMap.delete(record.ghsa_id); continue; }
        advisoryMap.set(record.ghsa_id, { id: record.ghsa_id, kind: 'advisory', cve: record.cve_id, name: record.summary, severity: record.severity, description: record.description?.slice(0, 5000) || '', cwes: (record.cwes || []).map((c) => c.cwe_id), publishedAt: record.published_at, updatedAt: record.updated_at, references: [record.html_url, ...(record.references || []).filter((r) => /^https:\/\//.test(r)).slice(0, 8)], vulnerabilities: record.vulnerabilities.map((v) => ({ ecosystem: v.package.ecosystem, name: v.package.name, range: v.vulnerable_version_range, fixed: v.first_patched_version })) });
      }
      url = response.next;
      if (url && new URL(url).origin !== 'https://api.github.com') throw new Error('Unexpected pagination destination');
    } catch (error) { errors.push(String(error.message)); break; }
  }
  console.log(`Targeted advisory records after ${ecosystem}: ${advisoryMap.size}`);
}
if (asvs.length < 300 || api.length < 10 || kev.length < 1000) throw new Error('Incomplete scenario sources; preserving previous extensions');
for (const [filename, url] of [['ASVS-LICENSE.md', 'https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0_release/LICENSE.md'], ['API-SECURITY-LICENSE.txt', `https://raw.githubusercontent.com/OWASP/API-Security/${apiCommit}/LICENSE`]]) await writeFile(path.join(output, filename), (await download(url)).buffer);
const result = { schemaVersion: 1, builtAt: new Date().toISOString(), sources, errors, asvsVersion: '5.0.0', apiVersion: '2023', apiCommit, kevVersion: kevSource.catalogVersion, asvs, api, kev, advisories: [...advisoryMap.values()], selection: 'ASVS v5.0.0 requirements; API Security 2023 risks/scenarios at pinned commit; CISA KEV full public catalog; bounded reviewed advisories for a fixed public package allowlist. No private project inventory is transmitted.' };
await writeFile(path.join(output, 'extensions.pending.json'), JSON.stringify(result) + '\n');
await rename(path.join(output, 'extensions.pending.json'), path.join(output, 'extensions.json'));
await writeFile(path.join(output, 'extensions-manifest.json'), JSON.stringify({ ...result, asvs: asvs.length, api: api.length, kev: kev.length, advisories: advisoryMap.size }, null, 2));
console.log(JSON.stringify({ asvs: asvs.length, api: api.length, kev: kev.length, targetedAdvisories: advisoryMap.size, errors }));
