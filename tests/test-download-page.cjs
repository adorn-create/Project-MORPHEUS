const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

async function runDownloadScript(releaseResponse) {
  const elements = new Map([
    ['#header-download', { href: '', textContent: '' }],
    ['#header-download-label', { textContent: '' }],
    ['#download-button', { href: '', textContent: '' }],
    ['#download-label', { textContent: '' }],
    ['#release-status', { textContent: '' }],
  ]);
  const errors = [];
  const context = {
    document: {
      querySelector: selector => elements.get(selector),
    },
    fetch: async () => releaseResponse,
    console: {
      error: (...args) => errors.push(args),
    },
  };
  vm.runInNewContext(fs.readFileSync('web/download.js', 'utf8'), context);
  await new Promise(resolve => setImmediate(resolve));
  return { elements, errors };
}

async function main() {
  const release = await runDownloadScript({
    ok: true,
    json: async () => ({
      tag_name: 'v0.1.4',
      assets: [{
        name: 'Morpheus Defense Setup 0.1.4.exe',
        browser_download_url: 'https://example.test/morpheus-0.1.4.exe',
        size: 198269111,
      }],
    }),
  });
  assert.equal(release.elements.get('#download-button').href, 'https://example.test/morpheus-0.1.4.exe');
  assert.equal(release.elements.get('#download-label').textContent, 'Download Windows App (.exe)');
  assert.equal(release.elements.get('#release-status').textContent, 'Latest release v0.1.4 · 189 MB');

  const fallback = await runDownloadScript({
    ok: false,
    status: 404,
  });
  const latestReleases = 'https://github.com/adorn-create/Project-MORPHEUS/releases/latest';
  assert.equal(fallback.elements.get('#header-download').href, latestReleases);
  assert.equal(fallback.elements.get('#download-button').href, latestReleases);
  assert.equal(fallback.elements.get('#download-label').textContent, 'View latest Windows release');
  assert.ok(!fallback.elements.get('#release-status').textContent.includes('v0.1.4'));
  assert.deepEqual(fallback.errors, []);
  console.log('Download page release and fallback checks passed.');
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
