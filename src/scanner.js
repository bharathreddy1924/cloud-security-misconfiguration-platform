const RULES = [
  {
    id: 'S3_PUBLIC_ACCESS',
    title: 'S3 bucket allows public access',
    severity: 'CRITICAL',
    description: 'Public bucket access can expose stored data to unauthorised users.',
    remediation: 'Enable all S3 Block Public Access settings and review bucket policies and ACLs.',
    check: r => r.type === 's3' && (r.publicAccess === true || r.blockPublicAccess === false)
  },
  {
    id: 'S3_ENCRYPTION_DISABLED',
    title: 'S3 default encryption is disabled',
    severity: 'HIGH',
    description: 'Objects may be stored without server-side encryption at rest.',
    remediation: 'Enable default server-side encryption using SSE-S3 or an approved KMS key.',
    check: r => r.type === 's3' && r.encryptionEnabled === false
  },
  {
    id: 'OPEN_SSH',
    title: 'SSH exposed to the internet',
    severity: 'CRITICAL',
    description: 'Port 22 is open to 0.0.0.0/0 or ::/0.',
    remediation: 'Restrict SSH to a trusted VPN, bastion host, or approved source CIDR.',
    check: r => r.type === 'security-group' && (r.ingress || []).some(x => Number(x.port) === 22 && ['0.0.0.0/0', '::/0'].includes(x.cidr))
  },
  {
    id: 'OPEN_RDP',
    title: 'RDP exposed to the internet',
    severity: 'CRITICAL',
    description: 'Port 3389 is open to 0.0.0.0/0 or ::/0.',
    remediation: 'Restrict RDP to a trusted VPN or approved source CIDR.',
    check: r => r.type === 'security-group' && (r.ingress || []).some(x => Number(x.port) === 3389 && ['0.0.0.0/0', '::/0'].includes(x.cidr))
  },
  {
    id: 'IAM_WILDCARD_POLICY',
    title: 'IAM policy grants wildcard permissions',
    severity: 'HIGH',
    description: 'A policy with Action or Resource set to * may grant excessive privileges.',
    remediation: 'Apply least privilege: specify only required actions and resource ARNs.',
    check: r => r.type === 'iam-policy' && (r.action === '*' || r.resource === '*')
  },
  {
    id: 'DATABASE_PUBLIC',
    title: 'Database is publicly accessible',
    severity: 'CRITICAL',
    description: 'A public database endpoint increases exposure to internet-based attacks.',
    remediation: 'Disable public accessibility and place the database in private subnets.',
    check: r => r.type === 'database' && r.publiclyAccessible === true
  },
  {
    id: 'CLOUDTRAIL_DISABLED',
    title: 'Cloud audit logging is disabled',
    severity: 'MEDIUM',
    description: 'Disabled audit logging reduces visibility into account activity.',
    remediation: 'Enable CloudTrail in all required regions and protect log integrity.',
    check: r => r.type === 'cloudtrail' && r.enabled === false
  },
  {
    id: 'EBS_ENCRYPTION_DISABLED',
    title: 'Block storage encryption is disabled',
    severity: 'MEDIUM',
    description: 'An unencrypted volume may expose data if the underlying storage is accessed.',
    remediation: 'Enable encryption by default and encrypt existing volumes during migration.',
    check: r => r.type === 'ebs' && r.encrypted === false
  }
];

function scanResources(resources) {
  if (!Array.isArray(resources)) throw new TypeError('resources must be an array');
  const findings = [];
  for (const resource of resources) {
    if (!resource || typeof resource !== 'object' || Array.isArray(resource)) continue;
    for (const rule of RULES) {
      try {
        if (rule.check(resource)) {
          findings.push({
            ruleId: rule.id,
            resourceId: String(resource.id || resource.name || 'unnamed-resource'),
            resourceType: String(resource.type || 'unknown'),
            title: rule.title,
            severity: rule.severity,
            description: rule.description,
            remediation: rule.remediation
          });
        }
      } catch (_) {
        // Malformed optional fields do not crash the full scan.
      }
    }
  }
  return findings;
}

module.exports = { scanResources, RULES };
