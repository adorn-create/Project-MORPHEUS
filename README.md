## Morpheus Defense MVP

A local Windows defensive endpoint prototype featuring process telemetry, an explainable proprietary behavior model, SQLite attack timelines, controlled quarantine, optional outbound firewall blocking, opt-in inbound scan blocking, and an API/dashboard.

## Safety defaults

- Firewall blocking is disabled by default and only runs when `automatic_high_confidence: true`.
- High-confidence process auto-quarantine is separately opt-in through the dashboard and remains recoverable.
- Outbound firewall rules block connections from this device; the separate, opt-in inbound scan feature blocks a public source IP from reaching this device. Morpheus cannot freeze a remote device, reliably identify an attacker from a connection IP, or guarantee that an observed address belongs to the person behind an intrusion.
- Review all detections before enabling automatic quarantine on a real device.

## Install

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
python -m pip install -e .
```

## Run

```powershell
python -c "from morpheus.main import cli; cli()" --scan
python -c "from morpheus.main import cli; cli()" --serve
```

Open <http://127.0.0.1:8080>.

## Desktop app

```powershell
npm install
npm run app
```

## Install the Python build extra before building the installer:

```powershell
python -m pip install -e ".[build]"
npm run build:win
```

`npm run build:win` bundles the Python backend and firewall worker as standalone Windows executables before creating the installer, so installed users do not need a project `.venv` or separate Python installation. The installer is machine-wide, installs under Windows' protected Program Files location, and requires administrator approval. The desktop app itself runs as a standard user. The desktop shell starts and supervises the backend, minimizes to the system tray, and exposes the dashboard, timeline, static file analysis, quarantine list, Sysmon status, firewall rules, and scan controls. Press **F11** for an immersive fullscreen dashboard; press **F11** or **Escape** to exit.

The Windows installer also packages a small, self-contained uninstall helper and adds an **Uninstall Morpheus Defense** shortcut to the Start Menu. The helper checks the standard Windows uninstall registration and opens Windows Apps settings; the device owner completes removal there. It does not gate uninstall with a password, rewrite uninstall registration, or delete files itself. The desktop app allows only one running instance and selects an available loopback port for its backend. Building the Windows installer requires the .NET 8 SDK to publish this helper.

If you have the earlier per-user build installed, uninstall it before installing this machine-wide release.

### Download website

The static download website is in `web/`. To publish it on Vercel, import this repository, set the root directory to `web`, choose the **Other** preset, and leave the build command empty. Enable Web Analytics in the Vercel project settings; the plain-HTML tracking script is in `web/index.html` (the `@vercel/analytics/next` component is for Next.js projects). GitHub Pages is also supported: first enable Pages under **Settings → Pages** and select **GitHub Actions** as the build source. The deployment workflow cannot publish until this repository setting exists.

To publish a Windows download, update the app version in `package.json`, push a matching version tag (for example, `v0.1.0`), and allow the **Publish Windows installer** workflow to complete. It builds and tests the installer, then attaches it to a GitHub Release. The download website will then link directly to that installer.

Development mode (`npm run app`) uses the active project `.venv`. If the packaged backend fails to start, Morpheus displays an error instead of crashing; startup details are written to the backend log under Electron's per-user application data folder.

### Built-in offline helper and code review

Morpheus includes a small, read-only offline helper with prepared explanations for common questions about alerts and app features. It needs no Ollama installation, model download, internet connection, or separate runtime. It is not a generative language model and cannot answer arbitrary questions, execute commands, quarantine items, or change settings.

File analysis is available through the desktop app's file and folder pickers. It reads selected files in bounded chunks and reports a fingerprint, heuristic warnings, and matches from a small bundled offline signature catalog. The catalog currently includes the harmless EICAR antivirus test string to verify that signature matching works; it is not a collection of current malware signatures. A match for EICAR is a scanner test, not a virus verdict. **Review source code offline** checks supported source files against Morpheus's built-in rules. Source contents stay on this computer; no external model or AI service is contacted. The rules can miss problems or flag safe code. Large scans may take a long time or use significant system resources. Windows and protected application locations are skipped. Morpheus operates independently of Microsoft Defender, but its small offline signature catalog and heuristics are not a replacement for a maintained antivirus product.

Python source review parses the complete source file with Python's built-in AST and checks syntax-tree calls and assignment flow for configured risks, including untrusted values reaching dynamic SQL. Other supported languages use the language-specific rules declared in `morpheus/rules/code_review.json`; those checks are pattern-based, not AST or full-program dataflow analysis. The rule loader validates the JSON schema and regexes at startup. The installer bundles this lightweight rule catalog.

The process behavior scorer and recent-event priority use the versioned JSON threat matrix in `morpheus/rules/threat_matrix.json`. Scores combine configured process indicators, recent event types, and a process-lineage correlation bonus, then normalize to documented score ranges. These weights are heuristic, hand-authored rather than trained from labeled data, and are not probabilities. Morpheus does not currently inspect Authenticode signatures, so it does not claim to detect unsigned executables.

The process activity scan observes process metadata, CPU use, established network connections, and a few command-line patterns. Command lines are checked in memory; raw arguments are not stored. It does not inspect executable contents or process memory. A separate, optional inbound scan monitor reads new dropped-packet entries from the Windows Firewall log. With **Automatic inbound scan blocking** explicitly enabled, it flags a public source address after dropped probes reach 10 distinct local ports within 60 seconds, then asks Windows Firewall to block that address from inbound traffic. It does not identify Nmap specifically or determine intent. The monitor requires dropped-packet logging to already be enabled by the device owner; Morpheus never changes that Windows setting. Existing log entries are ignored at startup. Monitoring reports unavailable if the log cannot be read. Use **Allow this IP** on an alert to remove Morpheus's inbound block and add the source to the persistent allowlist. Private/local source addresses are not automatically blocked.

The process scan also compares currently running executable names against a curated catalog of 70 common credential/password, network discovery, security testing, packet/wireless, tunneling, remote-access, and remote-administration tools. A match is a review-only alert because those tools also have legitimate uses. The catalog and command-pattern rules are not exhaustive: they do not reliably identify renamed binaries, generic interpreters, or unknown/new tools. Morpheus cannot guarantee discovery of every hacking tool or identify the person behind a connection.

When explicitly enabled, selected-folder monitoring periodically checks new or changed supported files in that folder and its subfolders. Existing files are used as a baseline, Windows and protected paths are skipped, and each poll tracks at most 5,000 supported files; a limit alert is recorded if the folder exceeds that cap. Monitoring runs on Morpheus's configured background polling interval (5 seconds by default), not as a kernel-level real-time scanner. A separate review-only signal is recorded when at least 25 supported files change within 60 seconds and at least five have high measured entropy. This is a conservative bulk-change heuristic, not ransomware identification; legitimate sync, archive, media, or development activity can trigger it. Morpheus does not stop processes or alter files in response to that signal. It has no cloud reputation, regularly refreshed malware signature feed, or broad antivirus engine, and cannot claim parity with Microsoft Defender.

### Expansion monitoring

The dashboard includes local, review-focused monitoring. Process-tree monitoring is enabled by default and stores process names, process IDs, and parent-child relationships; selected document applications spawning command/script hosts produce review alerts. A small ruleset also checks running command lines for a few unusual built-in tool patterns; raw command lines are not stored, only matched rule names and a hash. Neither feature inspects process memory. DNS entropy monitoring is off until enabled and periodically checks new names in the Windows DNS client cache; it is not packet capture and will miss queries that are not retained there. PowerShell event monitoring is off until enabled, reads new event ID 4104 records from the PowerShell Operational log, and works only when Windows Script Block Logging is already configured. Morpheus does not change logging policy. Script text is analyzed in memory and is not saved; alert records contain a hash and matched indicator names only.

The **Review startup entries** action reads common Windows `Run` and `RunOnce` registry locations and displays their values for manual review. It does not disable entries, inspect every persistence mechanism, or decide whether an entry is malicious. Registry access failures are shown, and long commands or large inventories are capped. This is a read-only audit, not a remediation feature.

Morpheus does not currently have a malware-feed update service, scheduled full-disk scanning, cloud reputation, AI-generated active rules, or an approval workflow for AI-proposed rules. Its offline helper only provides prepared explanations; it cannot change detection rules or execute actions. Automatic quarantine and firewall controls remain separate opt-in actions. The project does not self-modify or grant itself new permissions.

An optional canary monitor creates two harmless synthetic text files only inside Morpheus's own data directory and reports if they change or disappear. An explainable review-priority score correlates distinct alert types from the last 15 minutes; it is not a probability or malware verdict. All these are heuristic signals. They never terminate processes, restart themselves, isolate a device, or alter firewall, DNS, or ARP settings automatically. Any firewall change remains a separately confirmed action in the dashboard. Alerts are stored in the existing local SQLite event database and integrity journal. DNS and PowerShell telemetry can contain sensitive activity, so enable them only if appropriate for the device and its users.

The proposed port-trap listeners, automatic process/memory termination, YARA memory scanning, self-restarting anti-kill guardian, kernel/API hooks, automatic network micro-segmentation, domain-age lookups, ARP table changes, and packet interception are not implemented. They can disrupt the device, expose sensitive network data, or interfere with legitimate software; this prototype does not claim those capabilities.

### Optional standalone DNS/ARP review capture

`Advancement.py` can optionally inspect DNS and ARP packets on one explicitly selected interface. Install the optional dependency with `python -m pip install -e ".[network-monitoring]"`, list available interfaces with `python Advancement.py --list-interfaces`, then opt in using `python Advancement.py --capture-network --interface "INTERFACE NAME"`. On Windows, packet capture may require Npcap and permission to capture on that interface. The capture filter is limited to DNS (UDP/TCP port 53) and ARP; packet storage is disabled. DNS alerts retain only the queried name's SHA-256 and entropy details, not the name or packet. ARP alerts require an observed IP-to-MAC mapping change and are review-only. This standalone script is not bundled into the desktop dashboard, and it does not block, inject, replay, or alter network traffic.

The dashboard refresh reports the audit journal's last known verification state without rescanning the entire log every few seconds. To explicitly verify the complete journal, request `GET /api/journal/verify`. File analysis reads each file once while computing its hash and heuristic signals.

### Firewall worker and owner settings

The machine-wide installer registers a Windows service that runs with system privileges, but its named-pipe interface is restricted to the installing user's SID and it can only add outbound blocks, add inbound scan blocks, or remove Morpheus-owned firewall rules for globally routable IPv4 or IPv6 addresses. Morpheus manages rules in Windows Firewall; it is not a standalone firewall or kernel filtering driver. It cannot scan files, launch arbitrary commands, or modify unrelated firewall rules. Use the dashboard's firewall panels to make a change; blocking an address can interrupt network access. The service is stopped and removed by the normal Windows uninstaller.

To enable inbound scan monitoring, first enable **Log dropped packets** in Windows Defender Firewall with Advanced Security for the active profile (Properties → Logging → Customize). Then turn on **Automatic inbound scan blocking** in Morpheus and confirm the prompt. The setting is off by default. Morpheus does not enable Windows Firewall logging or turn on the Windows Firewall; firewall blocks cannot protect the device if Windows Firewall is disabled.

The dashboard can optionally protect security-setting and firewall changes with a locally chosen owner password (10 characters minimum). Only a salted PBKDF2 hash is stored under the user's Morpheus data directory; email registration and OTP are not used. This is a confirmation gate for the dashboard, not a security boundary against malware or other processes running as the same Windows user. It does **not** prevent the device owner from uninstalling Morpheus through Windows. If the password is forgotten, close Morpheus and remove `settings-password.json` from the user's Morpheus data folder to reset the dashboard password. Local administrators can still inspect or change local app data.

If the firewall worker service is installed but stopped, the dashboard reports its state and offers a start action that requests administrator approval. The privileged worker and installer are unsigned unless a publisher configures Authenticode signing. Do not treat this prototype as “military-grade,” tamper-proof, or a replacement for Windows Security.

The desktop app starts at Windows sign-in by default and can be disabled from its tray menu. Closing the dashboard window minimizes Morpheus to the tray; use the tray's Exit command to stop background monitoring. High-confidence process auto-quarantine is off by default and can be enabled in the dashboard. Download monitoring and download quarantine are separate, explicit opt-ins. In the dashboard, choose the folder to monitor; it can be on another drive (for example `D:\Downloads`). Monitoring checks newly arriving supported executable/script files at the top level of that folder; existing files are treated as already present, and it does not inspect archives, other folders, or intercept/prevent downloads. Selected downloads are analyzed locally. Quarantined files are recoverable, and the desktop app can show a notification when it quarantines a download. This prototype does not perform web reputation checks or provide an anonymizing VPN.

The prototype does not guarantee detection or prevention of every intrusion or download. Morpheus operates independently of Microsoft Defender and does not replace antivirus protection. Its firewall features require Windows Firewall to be enabled.

## Signed Windows release

The Windows installer build packages Electron's JavaScript app in an ASAR archive with Electron's embedded ASAR integrity validation enabled. For publisher verification, optionally configure an Authenticode signing certificate using `CSC_LINK` and `CSC_KEY_PASSWORD` in the build environment. Do not commit certificate files or passwords. Verify the installer publisher/signature in Windows before distributing it.

Code signing helps verify publisher identity and detect changes to the signed installer. It cannot make software unchangeable after download or installation; the device owner or an administrator can still modify or remove installed software. Python backend resources are not protected by Electron's ASAR integrity check. Do not describe this build as tamper-proof.

## Test

```powershell
python -m pytest
npm run test:ui
npm audit
```

### Vercel Web Analytics

The download website is plain HTML and uses the Vercel Analytics script in `web/index.html`. Enable Web Analytics in the Vercel project settings after deployment. The `@vercel/analytics/next` component is only for Next.js projects.
