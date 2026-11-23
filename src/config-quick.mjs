import path from 'node:path';
import { isMap, isScalar, isSeq, LineCounter, parseDocument } from 'yaml';

const workflowPermissions = {
  id: 'CFG-ACTIONS-WRITE-ALL', title: 'GitHub Actions grants write-all token permissions',
  cwe: 'CWE-250', severity: 'medium',
  condition: 'Review the effective GITHUB_TOKEN scopes for the workflow and its jobs.',
  impact: 'Workflow steps with access to the token may modify repository resources beyond what the job requires.',
  remediation: 'Set only the token permissions each job requires, using read access where possible.',
  reference: 'https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions',
};

const composeConfinement = {
  id: 'CFG-COMPOSE-UNCONFINED', title: 'Docker Compose disables container confinement',
  cwe: 'CWE-693', severity: 'medium',
  condition: 'Review the effective security profile for the service on the deployment host.',
  impact: 'The service runs without the configured syscall filtering or AppArmor confinement.',
  remediation: 'Use Docker’s default confinement or a profile limited to what the service needs.',
  reference: 'https://docs.docker.com/reference/compose-file/services/#security_opt',
};

export const QUICK_CONFIG_RULES = [workflowPermissions, composeConfinement];

const isWorkflow = (file) => /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(file);
const isCompose = (file) => /^(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$/i.test(path.posix.basename(file));
const mapItems = (node) => isMap(node) ? node.items : [];

export function scanQuickConfig(text, file, sourcePath, maxFindings) {
  const workflow = isWorkflow(sourcePath);
  if (!workflow && !isCompose(sourcePath)) return [];
  const lineCounter = new LineCounter();
  const doc = parseDocument(text, { lineCounter, prettyErrors: false });
  if (doc.errors.length) throw new Error('Invalid YAML');
  const findings = [];
  const add = (rule, node, evidence) => {
    if (findings.length >= maxFindings) return;
    const { line, col } = lineCounter.linePos(node.range[0]);
    findings.push({ ruleId: rule.id, title: rule.title, cwe: rule.cwe, severity: rule.severity,
      status: 'needs-review', confidence: 'high', location: { file, line, column: col }, evidence,
      impact: rule.impact, remediation: rule.remediation, reference: rule.reference,
      detection: { method: 'yaml-structure', condition: rule.condition } });
  };

  if (workflow) {
    const check = (node) => {
      const value = isMap(node) && node.get('permissions', true);
      if (isScalar(value) && value.value === 'write-all') add(workflowPermissions, value, 'permissions: write-all');
    };
    check(doc.contents);
    for (const { value } of mapItems(doc.get('jobs', true))) check(value);
  } else {
    for (const { value } of mapItems(doc.get('services', true))) {
      const options = isMap(value) && value.get('security_opt', true);
      if (!isSeq(options)) continue;
      for (const option of options.items) {
        if (!isScalar(option) || typeof option.value !== 'string') continue;
        const match = /^(seccomp|apparmor)\s*[:=]\s*unconfined$/.exec(option.value.trim());
        if (match) add(composeConfinement, option, `${match[1]}=unconfined`);
      }
    }
  }
  return findings;
}
