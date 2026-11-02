const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..');
const version = '1.5.4';
const archiveName = `clamav-${version}.win.x64.zip`;
const archiveUrl = `https://www.clamav.net/downloads/production/${archiveName}`;
const archiveSha256 = '0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395';
const buildRoot = path.join(projectRoot, 'clamav-build');
const archivePath = path.join(buildRoot, archiveName);
const outputDirectory = path.join(buildRoot, 'dist', 'clamav');

function fail(message) {
  console.error(message);
  process.exitCode = 1;
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: projectRoot,
    stdio: 'inherit',
    windowsHide: true,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} exited with status ${result.status}.`);
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function quotePowerShell(value) {
  return `'${value.replace(/'/g, "''")}'`;
}

try {
  if (process.platform !== 'win32') {
    throw new Error('The bundled ClamAV package is for 64-bit Windows builds only.');
  }

  fs.mkdirSync(buildRoot, { recursive: true });
  if (!fs.existsSync(archivePath) || sha256(archivePath) !== archiveSha256) {
    fs.rmSync(archivePath, { force: true });
    run('curl.exe', [
      '--fail',
      '--location',
      '--retry',
      '3',
      '--output',
      archivePath,
      archiveUrl,
    ]);
  }
  if (sha256(archivePath) !== archiveSha256) {
    throw new Error(`The downloaded ClamAV ${version} archive failed SHA-256 verification.`);
  }

  fs.rmSync(outputDirectory, { recursive: true, force: true });
  fs.mkdirSync(outputDirectory, { recursive: true });
  const extractionScript = [
    "$ErrorActionPreference = 'Stop'",
    'Add-Type -AssemblyName System.IO.Compression.FileSystem',
    `$archive = [System.IO.Compression.ZipFile]::OpenRead(${quotePowerShell(archivePath)})`,
    ` $destination = ${quotePowerShell(outputDirectory)}`,
    ` $prefix = 'clamav-${version}.win.x64/'`,
    ' $required = @()',
    ' try {',
    '   foreach ($entry in $archive.Entries) {',
    '     if (-not $entry.FullName.StartsWith($prefix)) { continue }',
    '     $relative = $entry.FullName.Substring($prefix.Length)',
    '     $isRuntime = (',
    "       $relative -match '^[^/]+\\.dll$' -or",
    "       $relative -in @('clamscan.exe', 'freshclam.exe') -or",
    "       $relative -match '^(certs|COPYING)/.+$'",
    '     )',
    '     if (-not $isRuntime -or $entry.Length -eq 0) { continue }',
    "     $target = Join-Path $destination $relative.Replace('/', [IO.Path]::DirectorySeparatorChar)",
    '     $parent = Split-Path -Parent $target',
    '     [IO.Directory]::CreateDirectory($parent) | Out-Null',
    '     [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)',
    '     $required += $relative',
    '   }',
    ' } finally {',
    '   $archive.Dispose()',
    ' }',
    " if ($required -notcontains 'clamscan.exe' -or $required -notcontains 'freshclam.exe') {",
    "   throw 'The verified ClamAV package is missing clamscan.exe or freshclam.exe.'",
    ' }',
  ].join('\n');
  run('powershell.exe', [
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-Command',
    extractionScript,
  ]);

  if (!fs.existsSync(path.join(outputDirectory, 'clamscan.exe'))
      || !fs.existsSync(path.join(outputDirectory, 'freshclam.exe'))) {
    throw new Error('ClamAV extraction did not produce both required executables.');
  }
  console.log(`Prepared ClamAV ${version} runtime and license files in ${outputDirectory}.`);
} catch (error) {
  fail(`Unable to prepare the bundled ClamAV runtime: ${error.message}`);
}
