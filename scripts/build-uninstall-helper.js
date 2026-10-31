const { spawnSync } = require('node:child_process');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..');
const result = spawnSync('dotnet', [
  'publish',
  path.join(projectRoot, 'uninstall-helper', 'MorpheusUninstallHelper.csproj'),
  '--configuration',
  'Release',
  '--runtime',
  'win-x64',
  '--self-contained',
  'true',
  '--output',
  path.join(projectRoot, 'uninstall-helper-build', 'publish'),
  '-p:PublishSingleFile=true',
  '-p:IncludeNativeLibrariesForSelfExtract=true',
], { cwd: projectRoot, stdio: 'inherit', windowsHide: true });

if (result.error) {
  console.error(`Unable to publish the Morpheus uninstall helper: ${result.error.message}`);
  process.exitCode = 1;
} else if (result.status !== 0) {
  process.exitCode = result.status || 1;
}
