const test = require('node:test');
const assert = require('node:assert/strict');
const { scanResources } = require('../src/scanner');

test('detects public S3 bucket and disabled encryption', () => {
  const findings = scanResources([{ id: 'bucket-1', type: 's3', publicAccess: true, encryptionEnabled: false }]);
  assert.deepEqual(findings.map(x => x.ruleId), ['S3_PUBLIC_ACCESS', 'S3_ENCRYPTION_DISABLED']);
});

test('detects internet-exposed SSH and RDP', () => {
  const findings = scanResources([{ id: 'sg-1', type: 'security-group', ingress: [
    { port: 22, cidr: '0.0.0.0/0' }, { port: 3389, cidr: '::/0' }
  ] }]);
  assert.deepEqual(findings.map(x => x.ruleId), ['OPEN_SSH', 'OPEN_RDP']);
});

test('detects wildcard IAM and public database', () => {
  const findings = scanResources([
    { id: 'policy-1', type: 'iam-policy', action: '*', resource: '*' },
    { id: 'db-1', type: 'database', publiclyAccessible: true }
  ]);
  assert.equal(findings.length, 2);
  assert.ok(findings.some(x => x.ruleId === 'IAM_WILDCARD_POLICY'));
  assert.ok(findings.some(x => x.ruleId === 'DATABASE_PUBLIC'));
});

test('does not report compliant sample resources', () => {
  const findings = scanResources([
    { id: 'bucket-safe', type: 's3', publicAccess: false, blockPublicAccess: true, encryptionEnabled: true },
    { id: 'db-safe', type: 'database', publiclyAccessible: false },
    { id: 'vol-safe', type: 'ebs', encrypted: true }
  ]);
  assert.equal(findings.length, 0);
});

test('ignores malformed entries without crashing', () => {
  assert.deepEqual(scanResources([null, 'bad', [], { id: 'x', type: 'security-group' }]), []);
});
