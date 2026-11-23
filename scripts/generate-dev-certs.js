#!/usr/bin/env node
/**
 * Local Development TLS Certificate Generator
 * 
 * Generates a self-signed X.509 TLS certificate with Subject Alternative Names (SAN)
 * for localhost and 127.0.0.1. Designed for local development and Nginx reverse proxy testing.
 * 
 * Safe execution: Does NOT overwrite existing certificates unless explicitly instructed via --force.
 */

const fs = require('fs');
const path = require('path');
const { execSync, spawnSync } = require('child_process');

const CERTS_DIR = path.join(__dirname, '..', 'nginx', 'certs');
const CERT_PATH = path.join(CERTS_DIR, 'cloudsec.crt');
const KEY_PATH = path.join(CERTS_DIR, 'cloudsec.key');

const isForce = process.argv.includes('--force') || process.argv.includes('-f');

function ensureDirectoryExists(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function findOpenSSL() {
  // 1. Try system PATH
  try {
    const res = spawnSync('openssl', ['version'], { stdio: 'pipe' });
    if (res.status === 0) return 'openssl';
  } catch (_) {}

  // 2. Try common Git for Windows installations
  const candidatePaths = [
    'C:\\Program Files\\Git\\usr\\bin\\openssl.exe',
    'C:\\Program Files (x86)\\Git\\usr\\bin\\openssl.exe',
    path.join(process.env.LOCALAPPDATA || '', 'Programs', 'Git', 'usr', 'bin', 'openssl.exe'),
    path.join(process.env.PROGRAMFILES || '', 'Git', 'usr', 'bin', 'openssl.exe')
  ];

  for (const p of candidatePaths) {
    if (p && fs.existsSync(p)) {
      return p;
    }
  }

  return null;
}

function generateWithOpenSSL(opensslBin) {
  console.log(`Using OpenSSL binary: ${opensslBin}`);

  const args = [
    'req',
    '-x509',
    '-newkey', 'rsa:2048',
    '-nodes',
    '-sha256',
    '-days', '365',
    '-subj', '/CN=localhost/O=CloudSec Development/OU=Capstone Security',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    '-keyout', KEY_PATH,
    '-out', CERT_PATH
  ];

  const result = spawnSync(opensslBin, args, { stdio: 'inherit' });
  if (result.status !== 0) {
    throw new Error(`OpenSSL execution failed with exit code ${result.status}`);
  }
}

function generateWithPowerShell() {
  console.log('OpenSSL binary not found. Falling back to Windows PowerShell PKI module...');

  const psScript = `
    $cert = New-SelfSignedCertificate -DnsName "localhost", "127.0.0.1" -CertStoreLocation "Cert:\\CurrentUser\\My" -NotAfter (Get-Date).AddYears(1) -KeyExportPolicy Exportable -KeySpec Signature
    $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $certPem = "-----BEGIN CERTIFICATE-----\`n" + [System.Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks) + "\`n-----END CERTIFICATE-----\`n"
    [System.IO.File]::WriteAllText("${CERT_PATH.replace(/\\/g, '\\\\')}", $certPem)

    # Export RSA private key
    $rsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    $keyBytes = $rsaKey.ExportPkcs8PrivateKey()
    $keyPem = "-----BEGIN PRIVATE KEY-----\`n" + [System.Convert]::ToBase64String($keyBytes, [System.Base64FormattingOptions]::InsertLineBreaks) + "\`n-----END PRIVATE KEY-----\`n"
    [System.IO.File]::WriteAllText("${KEY_PATH.replace(/\\/g, '\\\\')}", $keyPem)

    # Clean up from personal store
    Remove-Item -Path "Cert:\\CurrentUser\\My\\$($cert.Thumbprint)" -Force
  `;

  execSync(`powershell -NoProfile -Command "${psScript.replace(/\n/g, ' ')}"`, { stdio: 'inherit' });
}

function main() {
  console.log('=== CloudSec Local Development TLS Certificate Generator ===');
  ensureDirectoryExists(CERTS_DIR);

  const certExists = fs.existsSync(CERT_PATH);
  const keyExists = fs.existsSync(KEY_PATH);

  if (certExists && keyExists && !isForce) {
    console.log('✓ Valid TLS certificate and private key already exist:');
    console.log(`  Certificate: ${CERT_PATH}`);
    console.log(`  Private Key: ${KEY_PATH}`);
    console.log('  Subject Alternative Names (SAN): DNS:localhost, IP:127.0.0.1');
    console.log('\n[NOTICE] Existing certificates were NOT overwritten.');
    console.log('To regenerate and overwrite, run: node scripts/generate-dev-certs.js --force\n');
    return;
  }

  if (certExists || keyExists) {
    console.log('[NOTICE] Overwriting existing certificate and private key (--force specified)...');
  } else {
    console.log('Generating new local self-signed TLS certificate with SAN entries...');
  }

  const opensslBin = findOpenSSL();

  if (opensslBin) {
    generateWithOpenSSL(opensslBin);
  } else if (process.platform === 'win32') {
    generateWithPowerShell();
  } else {
    throw new Error('Unable to find OpenSSL or a supported platform certificate generator.');
  }

  if (fs.existsSync(CERT_PATH) && fs.existsSync(KEY_PATH)) {
    console.log('\n✓ TLS certificate and private key generated successfully:');
    console.log(`  Certificate : ${CERT_PATH}`);
    console.log(`  Private Key : ${KEY_PATH}`);
    console.log('  SAN Entries : DNS:localhost, IP:127.0.0.1');
    console.log('  Validity    : 365 Days');
    console.log('\n[SECURITY NOTE] These certificates are gitignored and intended for local development only.\n');
  } else {
    throw new Error('Certificate generation completed but output files were not found.');
  }
}

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error('❌ Error generating TLS certificates:', err.message);
    process.exit(1);
  }
}

module.exports = { main, findOpenSSL, CERT_PATH, KEY_PATH };
