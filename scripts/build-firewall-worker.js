const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..');
const localPython = path.join(projectRoot, '.venv', 'Scripts', 'python.exe');
const python = process.env.MORPHEUS_BUILD_PYTHON || (fs.existsSync(localPython) ? localPython : 'python');
const result = spawnSync(python, [
  '-m',
  'PyInstaller',
  '--noconfirm',
  '--clean',
  '--distpath',
  path.join(projectRoot, 'worker-build', 'dist'),
  '--workpath',
  path.join(projectRoot, 'worker-build', 'work'),
  path.join(projectRoot, 'firewall_worker.spec'),
], { cwd: projectRoot, stdio: 'inherit', windowsHide: true });

if (result.error) {
  console.error(`Unable to run the firewall worker build: ${result.error.message}`);
  process.exitCode = 1;
} else if (result.status !== 0) {
  process.exitCode = result.status || 1;
}
