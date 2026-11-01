const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

class Element {
  constructor(id = '') {
    this.id = id;
    this.listeners = new Map();
    this.children = [];
    this.className = '';
    this.attributes = new Map();
    this.classes = new Set();
    this.classList = {
      toggle: (name, enabled) => {
        if (enabled) this.classes.add(name);
        else this.classes.delete(name);
      },
      contains: name => this.classes.has(name),
    };
    this.value = '';
    this.checked = false;
    this.disabled = false;
    this.files = [];
    this.textContent = '';
  }

  addEventListener(name, callback) {
    this.listeners.set(name, callback);
  }

  setAttribute(name, value) {
    this.attributes.set(name, value);
  }

  focus() {}

  async dispatch(name, event = {}) {
    const callback = this.listeners.get(name);
    assert.ok(callback, `${this.id || 'element'} has a ${name} handler`);
    return callback({ target: this, key: '', ...event });
  }

  append(...items) {
    this.children.push(...items);
  }

  appendChild(item) {
    this.children.push(item);
    return item;
  }

  replaceChildren(...items) {
    this.children = items;
  }

  get lastElementChild() {
    return this.children.at(-1) || new Element(`${this.id}-status`);
  }
}

const ids = [
  'runScanButton', 'scanPanelButton', 'refreshButton', 'scanStatus',
  'connectionStatus', 'fileScanButton', 'browseFileButton', 'browseFolderButton',
  'reviewCodeButton', 'folderInput',
  'scanResult', 'folderResults', 'downloadMonitoring', 'quarantineDownloads',
  'automaticQuarantine', 'eventsBody', 'timeline', 'sysmonStatus',
  'dnsEntropyMonitoring', 'powershellLogMonitoring', 'processTreeMonitoring',
  'canaryMonitoring', 'dnsMonitorStatus', 'powershellMonitorStatus',
  'canaryMonitorStatus', 'processTree', 'riskLevel', 'riskDetails',
  'assistantStatus', 'assistantConversation',
  'assistantForm', 'assistantQuestion', 'sendAssistantQuestion',
  'downloadDirectoryPath', 'browseDownloadFolderButton',
  'eventCount', 'monitoringState', 'lastScanTime', 'downloadMonitorState',
  'quarantineState', 'toolCatalogCount', 'settingsPasswordState',
  'settingsPasswordButton', 'settingsPasswordForm', 'passwordFormMessage',
  'ownerPasswordInput', 'newOwnerPassword', 'confirmOwnerPassword',
  'cancelOwnerPasswordButton', 'firewallRules', 'firewallWorkerState',
  'startFirewallWorkerButton', 'firewallActionStatus', 'addFirewallRuleButton',
  'firewallIp', 'scanPath',
];
const elements = new Map(ids.map(id => [id, new Element(id)]));
const calls = [];
let passwordConfigured = false;
let workerAvailable = false;
let refreshTimer = null;
let eventsData = [];
let processTreeData = {
  nodes: [{ pid: 10, parent_pid: 1, name: 'explorer.exe' }],
  edges: [],
  total_processes: 1,
  truncated: false,
};
let config = {
  automatic_quarantine: false,
  download_monitoring: false,
  automatic_quarantine_downloads: false,
  dns_entropy_monitoring: false,
  powershell_log_monitoring: false,
  process_tree_monitoring: true,
  canary_monitoring: false,
  high_confidence_threshold: 0.95,
};
let selectedFolder = null;
const fullScreenListeners = [];

function response(data, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(data),
  };
}

async function fetch(url, options = {}) {
  const method = options.method || 'GET';
  calls.push({ url, method, options });
  if (url === '/api/events' || url === '/api/timeline') {
    return response(url === '/api/events' ? eventsData : []);
  }
  if (url === '/api/process-tree') {
    return response(processTreeData);
  }
  if (url === '/api/risk') {
    return response({
      score: 0,
      level: 'normal',
      window_minutes: 15,
      signals: [],
      explanation: 'This is not a probability.',
    });
  }
  if (url === '/api/firewall' && method === 'GET') {
    return response([{ name: 'Morpheus-Block-012345abcdef', remote_ip: '8.8.8.8' }]);
  }
  if (url === '/api/sysmon') {
    return response({ installed: false, install_help: '' });
  }
  if (url === '/api/assistant/status') {
    return response({
      available: true,
      ready: true,
      models: ['morpheus-offline-v1'],
      message: 'Morpheus built-in offline helper is ready.',
    });
  }
  if (url === '/api/assistant/chat' && method === 'POST') {
    return response({
      model: 'Morpheus offline helper',
      answer: 'An alert is a warning to review, not proof of infection.',
    });
  }
  if (url === '/api/status') {
    return response({
      event_count: 0,
      monitoring: { running: true, poll_interval_seconds: 5, downloads_enabled: false },
      tool_watch: { catalog_entries: 70 },
      expansion: {
        dns: { enabled: false, available: true, message: 'Off.' },
        powershell: { enabled: false, available: true, message: 'Off.' },
        process_tree_enabled: true,
        canary: { enabled: false, directory: 'test-data', files: 2, message: 'Off.' },
      },
      config,
    });
  }
  if (url === '/api/settings-password/status') return response({ configured: passwordConfigured });
  if (url === '/api/firewall/worker') {
    return response({
      available: workerAvailable,
      installed: true,
      running: workerAvailable,
      message: workerAvailable ? 'The firewall service is ready.' : 'The firewall service is installed but stopped.',
    });
  }
  if (url === '/api/review-code' && method === 'POST') {
    return response({
      path: JSON.parse(options.body).path,
      files_scanned: 1,
      findings: [{
        reviewer: 'Morpheus rules',
        severity: 'high',
        path: 'sample.py',
        line: 4,
        title: 'Potential hard-coded credential',
        explanation: 'A credential may be embedded in the code.',
        remediation: 'Move credentials to protected configuration.',
      }],
      failures: [],
      truncated: false,
      ruleset: 'Morpheus offline AST and JSON rules v2',
    });
  }
  if (url === '/api/scan' && method === 'POST') return response({ detected: [], processes_checked: 42 });
  if (url === '/api/scan-file' && method === 'POST') {
    return response({ path: 'sample.exe', size: 2, confidence: 0, reasons: [] });
  }
  if (url === '/api/scan-folder' && method === 'POST') {
    return response({ results: [], failures: [], skipped_system_paths: 0 });
  }
  if (url === '/api/settings-password' && method === 'POST') {
    passwordConfigured = true;
    return response({ configured: true });
  }
  if (url === '/api/config' && method === 'POST') {
    config = { ...config, ...JSON.parse(options.body) };
    return response(config);
  }
  if (url === '/api/firewall' && method === 'POST') return response({ added: true });
  if (url.startsWith('/api/firewall/') && method === 'DELETE') return response({ removed: true });
  return response({ detail: `Unexpected test request: ${method} ${url}` }, 404);
}

const document = {
  body: new Element('body'),
  documentElement: new Element('documentElement'),
  addEventListener() {},
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, new Element(id));
    return elements.get(id);
  },
  createElement: tag => new Element(tag),
};
const window = {
  confirm: () => true,
  alert: message => { throw new Error(message); },
  morpheus: {
    selectFile: async () => 'C:\\Users\\Owner\\sample.exe',
    selectFolder: async () => selectedFolder,
    selectDownloadFolder: async () => selectedFolder,
    onFullScreenChanged: callback => fullScreenListeners.push(callback),
    startFirewallService: async () => { workerAvailable = true; },
  },
};

async function main() {
  const html = fs.readFileSync('morpheus/templates/dashboard.html', 'utf8');
  const downloadSite = fs.readFileSync('web/index.html', 'utf8');
  assert.match(downloadSite, /<img class="brand-mark" src="favicon\.svg" alt="">/);
  const start = html.indexOf('<script>');
  const end = html.indexOf('</script>', start);
  assert.notEqual(start, -1, 'dashboard script exists');
  vm.runInNewContext(html.slice(start + 8, end), {
    AbortSignal,
    FormData,
    Promise,
    document,
    fetch,
    setInterval: callback => { refreshTimer = callback; return 1; },
    setTimeout: callback => { callback(); return 1; },
    window,
  });
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));

  assert.equal(elements.get('runScanButton').listeners.has('click'), true);
  assert.equal(elements.has('fullscreenButton'), false, 'F11 remains a shortcut without an on-screen button');
  fullScreenListeners[0](true);
  assert.equal(document.body.classList.contains('is-fullscreen'), true);
  fullScreenListeners[0](false);
  assert.equal(document.body.classList.contains('is-fullscreen'), false);

  await elements.get('runScanButton').dispatch('click');
  assert.ok(calls.some(call => call.url === '/api/scan' && call.method === 'POST'));

  await elements.get('scanPanelButton').dispatch('click');
  assert.equal(calls.filter(call => call.url === '/api/scan').length, 2);
  assert.match(elements.get('scanStatus').textContent, /Checked 42 running apps/);
  assert.equal(calls.some(call => call.url === '/api/assistant/status'), false);
  elements.get('assistantQuestion').value = 'What does this alert mean?';
  await elements.get('assistantForm').dispatch('submit', { preventDefault() {} });
  const assistantCall = calls.find(call => call.url === '/api/assistant/chat' && call.method === 'POST');
  assert.ok(assistantCall);
  assert.deepEqual(JSON.parse(assistantCall.options.body), { message: 'What does this alert mean?' });
  assert.match(elements.get('assistantStatus').textContent, /Offline Helper replied/i);
  assert.equal(
    elements.get('assistantConversation').children.at(-1).textContent,
    'An alert is a warning to review, not proof of infection.'
  );

  await elements.get('refreshButton').dispatch('click');
  processTreeData = {
    nodes: [],
    edges: Array.from({ length: 30 }, (_, index) => ({
      parent_name: `parent-${index}`,
      child_name: `child-${index}`,
      review: false,
    })),
    total_processes: 31,
    truncated: false,
  };
  await elements.get('refreshButton').dispatch('click');
  assert.equal(elements.get('processTree').children.length, 31, 'all app relationships are shown');
  eventsData = [{
    kind: 'suspicious_process',
    severity: 'medium',
    source: 'example.exe',
    target: 'local review',
    evidence: JSON.stringify([{ description: 'A local warning pattern was matched.' }]),
  }];
  await elements.get('refreshButton').dispatch('click');
  assert.equal(elements.get('eventsBody').children[0].children[4].textContent, 'A local warning pattern was matched.');
  assert.doesNotMatch(elements.get('eventsBody').children[0].children[4].textContent, /\[object Object\]/);
  processTreeData = {
    nodes: [{ pid: 10, parent_pid: 1, name: 'explorer.exe' }],
    edges: [],
    total_processes: 1,
    truncated: false,
  };
  const firewallReadsAfterManualRefresh = calls.filter(
    call => call.url === '/api/firewall' && call.method === 'GET'
  ).length;
  assert.ok(firewallReadsAfterManualRefresh >= 1);
  refreshTimer();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(
    calls.filter(call => call.url === '/api/firewall' && call.method === 'GET').length,
    firewallReadsAfterManualRefresh,
    'background refresh does not rerun expensive firewall enumeration'
  );
  elements.get('scanPath').value = 'C:\\Users\\Owner\\sample.exe';
  await elements.get('fileScanButton').dispatch('click');
  assert.ok(calls.some(call => call.url === '/api/scan-file' && call.method === 'POST'));
  assert.match(elements.get('scanResult').textContent, /no known warning signs/i);
  elements.get('scanPath').value = 'C:\\Users\\Owner\\sample.py';
  await elements.get('reviewCodeButton').dispatch('click');
  const codeReviewCall = calls.find(call => call.url === '/api/review-code' && call.method === 'POST');
  assert.ok(codeReviewCall);
  assert.deepEqual(JSON.parse(codeReviewCall.options.body), { path: 'C:\\Users\\Owner\\sample.py' });
  assert.match(elements.get('scanResult').textContent, /1 finding/);
  assert.equal(elements.get('folderResults').children[0].children[1].children[0].children[1].textContent, 'HIGH');

  selectedFolder = 'C:\\Users\\Owner\\Documents';
  await elements.get('browseFolderButton').dispatch('click');
  assert.ok(calls.some(call => call.url === '/api/scan-folder' && call.method === 'POST'));
  await elements.get('browseFileButton').dispatch('click');
  assert.equal(elements.get('scanPath').value, 'C:\\Users\\Owner\\sample.exe');

  const removeButton = elements.get('firewallRules').children[0].children[1];
  await removeButton.dispatch('click');
  assert.ok(calls.some(call => call.url === '/api/firewall/Morpheus-Block-012345abcdef' && call.method === 'DELETE'));

  await elements.get('settingsPasswordButton').dispatch('click');
  assert.equal(elements.get('settingsPasswordForm').hidden, false);
  elements.get('newOwnerPassword').value = 'Abcdef123';
  elements.get('confirmOwnerPassword').value = 'Abcdef123';
  await elements.get('settingsPasswordForm').dispatch('submit', { preventDefault() {} });
  assert.match(elements.get('passwordFormMessage').textContent, /at least 10 characters/i);
  assert.equal(calls.some(call => call.url === '/api/settings-password'), false);

  elements.get('newOwnerPassword').value = 'Abcdef1234';
  elements.get('confirmOwnerPassword').value = 'Abcdef1234';
  await elements.get('settingsPasswordForm').dispatch('submit', { preventDefault() {} });
  assert.ok(calls.some(call => call.url === '/api/settings-password' && call.method === 'POST'));

  elements.get('ownerPasswordInput').value = 'Abcdef1234';
  elements.get('firewallIp').value = '8.8.8.8';
  await elements.get('addFirewallRuleButton').dispatch('click');
  assert.ok(calls.some(call => call.url === '/api/firewall' && call.method === 'POST'));

  await elements.get('startFirewallWorkerButton').dispatch('click');
  assert.equal(workerAvailable, true);

  elements.get('ownerPasswordInput').value = 'a-long-owner-password';
  const quarantine = elements.get('automaticQuarantine');
  quarantine.checked = true;
  await quarantine.dispatch('change');
  assert.ok(calls.some(call => call.url === '/api/config' && call.method === 'POST'));

  const downloads = elements.get('downloadMonitoring');
  downloads.checked = true;
  await downloads.dispatch('change');
  assert.ok(calls.filter(call => call.url === '/api/config' && call.method === 'POST').length >= 2);
  selectedFolder = 'D:\\Custom Downloads';
  await elements.get('browseDownloadFolderButton').dispatch('click');
  const directoryCall = calls.find(call =>
    call.url === '/api/config'
    && JSON.parse(call.options.body).download_directory === 'D:\\Custom Downloads'
  );
  assert.ok(directoryCall, 'selected alternate-drive Downloads folder is saved');
  assert.equal(elements.get('downloadDirectoryPath').value, 'D:\\Custom Downloads');

  const quarantineDownloads = elements.get('quarantineDownloads');
  quarantineDownloads.checked = true;
  await quarantineDownloads.dispatch('change');
  assert.equal(calls.filter(call => call.url === '/api/config' && call.method === 'POST').length, 3);

  elements.get('ownerPasswordInput').value = 'a-long-owner-password';
  elements.get('dnsEntropyMonitoring').checked = true;
  await elements.get('dnsEntropyMonitoring').dispatch('change');
  assert.ok(calls.some(call => call.url === '/api/config' && JSON.parse(call.options.body).dns_entropy_monitoring === true));
  elements.get('powershellLogMonitoring').checked = true;
  await elements.get('powershellLogMonitoring').dispatch('change');
  assert.ok(calls.some(call => call.url === '/api/config' && JSON.parse(call.options.body).powershell_log_monitoring === true));
  elements.get('processTreeMonitoring').checked = false;
  await elements.get('processTreeMonitoring').dispatch('change');
  assert.ok(calls.some(call => call.url === '/api/config' && JSON.parse(call.options.body).process_tree_monitoring === false));
  assert.match(elements.get('processTree').children[0].textContent, /1 running app/);
  elements.get('canaryMonitoring').checked = true;
  await elements.get('canaryMonitoring').dispatch('change');
  assert.ok(calls.some(call => call.url === '/api/config' && JSON.parse(call.options.body).canary_monitoring === true));
  assert.equal(elements.get('riskLevel').textContent, 'No recent warning signs');
}

main().then(() => {
  console.log('Dashboard button handlers executed successfully.');
}).catch(error => {
  console.error(error);
  process.exitCode = 1;
});
