#!/usr/bin/env node
'use strict';

const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');

const DEFAULT_REPO = 'MuhDur/oraclemcp';
const OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
const MAX_REDIRECTS = 5;

function readPackage() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
}

function normalizeVersion(version) {
  if (!version || version === 'latest') {
    return 'latest';
  }
  const clean = version.startsWith('v') ? version.slice(1) : version;
  if (!/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(clean)) {
    throw new Error(`unsupported ORACLEMCP_NPM_RELEASE '${version}'`);
  }
  return clean;
}

function targetFor(platform = process.platform, arch = process.arch) {
  if (platform === 'linux' && arch === 'x64') {
    return 'x86_64-unknown-linux-musl';
  }
  if (platform === 'linux' && arch === 'arm64') {
    return 'aarch64-unknown-linux-musl';
  }
  if (platform === 'darwin' && arch === 'x64') {
    return 'x86_64-apple-darwin';
  }
  if (platform === 'darwin' && arch === 'arm64') {
    return 'aarch64-apple-darwin';
  }
  if (platform === 'win32' && arch === 'x64') {
    return 'x86_64-pc-windows-msvc';
  }
  throw new Error(`unsupported platform '${platform}/${arch}'`);
}

function archiveExtension(target) {
  return target.endsWith('-pc-windows-msvc') ? '.zip' : '.tar.gz';
}

function binaryName() {
  return process.platform === 'win32' ? 'oraclemcp.exe' : 'oraclemcp';
}

function assetName(target) {
  return `oraclemcp-${target}${archiveExtension(target)}`;
}

function releaseTag(version) {
  return version === 'latest' ? 'latest' : `v${version}`;
}

function releaseBaseUrl(repo, version) {
  if (version === 'latest') {
    return `https://github.com/${repo}/releases/latest/download`;
  }
  return `https://github.com/${repo}/releases/download/${releaseTag(version)}`;
}

function identityArgs(repo, version) {
  if (version === 'latest') {
    return [
      '--certificate-identity-regexp',
      `https://github[.]com/${repo}/[.]github/workflows/release[.]yml@refs/tags/v[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?`,
    ];
  }
  return [
    '--certificate-identity',
    `https://github.com/${repo}/.github/workflows/release.yml@refs/tags/v${version}`,
  ];
}

function cacheRoot() {
  if (process.env.ORACLEMCP_NPM_CACHE) {
    return path.resolve(process.env.ORACLEMCP_NPM_CACHE);
  }
  if (process.platform === 'win32' && process.env.LOCALAPPDATA) {
    return path.join(process.env.LOCALAPPDATA, 'oraclemcp', 'npm');
  }
  if (process.env.XDG_CACHE_HOME) {
    return path.join(process.env.XDG_CACHE_HOME, 'oraclemcp', 'npm');
  }
  return path.join(os.homedir(), '.cache', 'oraclemcp', 'npm');
}

function buildPlan() {
  const pkg = readPackage();
  const version = normalizeVersion(process.env.ORACLEMCP_NPM_RELEASE || pkg.version);
  const repo = process.env.ORACLEMCP_NPM_REPO || DEFAULT_REPO;
  const target = targetFor();
  const asset = assetName(target);
  const base = releaseBaseUrl(repo, version);
  const cacheBinary = path.join(cacheRoot(), version, target, binaryName());
  const archiveUrl = `${base}/${asset}`;
  return {
    package: pkg.name,
    packageVersion: pkg.version,
    release: version,
    repo,
    target,
    asset,
    archiveUrl,
    checksumUrl: `${archiveUrl}.sha256`,
    signatureUrl: `${archiveUrl}.sig`,
    certificateUrl: `${archiveUrl}.crt`,
    attestationUrl: `${archiveUrl}.attestation.sigstore.json`,
    cacheBinary,
    verification: ['sha256', 'cosign verify-blob', 'cosign verify-blob-attestation'],
    serviceMutation: false,
    clientCredentialMutation: false,
  };
}

function downloadFile(url, dest, redirects = 0) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, { headers: { 'user-agent': 'oraclemcp-npm-wrapper' } }, (res) => {
      if (
        res.statusCode >= 300 &&
        res.statusCode < 400 &&
        res.headers.location &&
        redirects < MAX_REDIRECTS
      ) {
        res.resume();
        const next = new URL(res.headers.location, url).toString();
        downloadFile(next, dest, redirects + 1).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`download failed for ${url}: HTTP ${res.statusCode}`));
        return;
      }
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      const out = fs.createWriteStream(dest, { mode: 0o600 });
      res.pipe(out);
      out.on('finish', () => out.close(resolve));
      out.on('error', reject);
    });
    request.on('error', reject);
  });
}

function checksumFromFile(checksumPath) {
  const text = fs.readFileSync(checksumPath, 'utf8');
  const match = text.match(/\b[a-fA-F0-9]{64}\b/);
  if (!match) {
    throw new Error(`checksum file ${checksumPath} does not contain a SHA-256 digest`);
  }
  return match[0].toLowerCase();
}

function verifyChecksum(archivePath, checksumPath) {
  const expected = checksumFromFile(checksumPath);
  const actual = crypto.createHash('sha256').update(fs.readFileSync(archivePath)).digest('hex');
  if (actual !== expected) {
    throw new Error(`checksum mismatch for ${path.basename(archivePath)}: expected ${expected}, got ${actual}`);
  }
}

function runChecked(command, args, options = {}) {
  const result = childProcess.spawnSync(command, args, { stdio: 'inherit', ...options });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} exited with ${result.status}`);
  }
}

function verifyCosign(plan, archivePath, signaturePath, certificatePath, attestationPath) {
  const cosign = process.env.ORACLEMCP_COSIGN || 'cosign';
  const identity = identityArgs(plan.repo, plan.release);
  runChecked(cosign, [
    'verify-blob',
    '--certificate',
    certificatePath,
    '--signature',
    signaturePath,
    ...identity,
    '--certificate-oidc-issuer',
    OIDC_ISSUER,
    archivePath,
  ]);
  runChecked(cosign, [
    'verify-blob-attestation',
    '--bundle',
    attestationPath,
    '--type',
    'slsaprovenance1',
    ...identity,
    '--certificate-oidc-issuer',
    OIDC_ISSUER,
    archivePath,
  ]);
}

function extractArchive(archivePath, plan, tmpDir) {
  const extractDir = path.join(tmpDir, 'extract');
  fs.mkdirSync(extractDir, { recursive: true });
  if (plan.asset.endsWith('.tar.gz')) {
    runChecked('tar', ['-xzf', archivePath, '-C', extractDir]);
  } else {
    const ps = process.platform === 'win32' ? 'powershell.exe' : 'pwsh';
    const result = childProcess.spawnSync(
      ps,
      [
        '-NoLogo',
        '-NoProfile',
        '-Command',
        'Expand-Archive -LiteralPath $args[0] -DestinationPath $args[1] -Force',
        archivePath,
        extractDir,
      ],
      { stdio: 'inherit' },
    );
    if (result.error || result.status !== 0) {
      runChecked('tar', ['-xf', archivePath, '-C', extractDir]);
    }
  }
  const extracted = path.join(extractDir, `oraclemcp-${plan.target}`, binaryName());
  if (!fs.existsSync(extracted)) {
    throw new Error(`release archive did not contain ${extracted}`);
  }
  return extracted;
}

async function installToCache(plan) {
  if (fs.existsSync(plan.cacheBinary)) {
    return plan.cacheBinary;
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'oraclemcp-npm-'));
  try {
    const archivePath = path.join(tmpDir, plan.asset);
    const checksumPath = `${archivePath}.sha256`;
    const signaturePath = `${archivePath}.sig`;
    const certificatePath = `${archivePath}.crt`;
    const attestationPath = `${archivePath}.attestation.sigstore.json`;

    await downloadFile(plan.archiveUrl, archivePath);
    await downloadFile(plan.checksumUrl, checksumPath);
    await downloadFile(plan.signatureUrl, signaturePath);
    await downloadFile(plan.certificateUrl, certificatePath);
    await downloadFile(plan.attestationUrl, attestationPath);

    verifyChecksum(archivePath, checksumPath);
    verifyCosign(plan, archivePath, signaturePath, certificatePath, attestationPath);

    const extracted = extractArchive(archivePath, plan, tmpDir);
    fs.mkdirSync(path.dirname(plan.cacheBinary), { recursive: true });
    fs.copyFileSync(extracted, plan.cacheBinary);
    if (process.platform !== 'win32') {
      fs.chmodSync(plan.cacheBinary, 0o755);
    }
    return plan.cacheBinary;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function invokedName() {
  const base = path.basename(process.argv[1] || 'oraclemcp').replace(/\.js$/i, '');
  return base === 'om' ? 'om' : 'oraclemcp';
}

async function main() {
  const args = process.argv.slice(2);
  const dryRunIndex = args.indexOf('--oraclemcp-npm-dry-run');
  const dryRun = process.env.ORACLEMCP_NPM_DRY_RUN === '1' || dryRunIndex !== -1;
  if (dryRunIndex !== -1) {
    args.splice(dryRunIndex, 1);
  }

  const plan = buildPlan();
  if (dryRun) {
    process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
    return;
  }

  const binary = await installToCache(plan);
  const child = childProcess.spawn(binary, args, {
    stdio: 'inherit',
    argv0: invokedName(),
  });
  child.on('error', (error) => {
    console.error(`oraclemcp npm wrapper: ${error.message}`);
    process.exit(1);
  });
  child.on('exit', (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 1);
  });
}

module.exports = {
  buildPlan,
  targetFor,
};

if (require.main === module) {
  main().catch((error) => {
    console.error(`oraclemcp npm wrapper: ${error.message}`);
    process.exit(1);
  });
}
