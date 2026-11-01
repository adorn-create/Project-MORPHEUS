const repository = 'adorn-create/Project-MORPHEUS';
const releaseUrl = `https://api.github.com/repos/${repository}/releases/latest`;
const currentInstallerUrl = `https://github.com/${repository}/releases/download/v0.1.3/Morpheus.Defense.Setup.0.1.3.exe`;
const headerDownload = document.querySelector('#header-download');
const headerDownloadLabel = document.querySelector('#header-download-label');
const downloadButton = document.querySelector('#download-button');
const downloadLabel = document.querySelector('#download-label');
const releaseStatus = document.querySelector('#release-status');

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '';
  return `${(bytes / (1024 * 1024)).toFixed(0)} MB`;
}

function useReleaseFallback(message) {
  headerDownload.href = currentInstallerUrl;
  headerDownloadLabel.textContent = 'Download .exe';
  downloadButton.href = currentInstallerUrl;
  downloadLabel.textContent = 'Download Windows App (.exe)';
  releaseStatus.textContent = message;
}

async function loadLatestRelease() {
  try {
    const response = await fetch(releaseUrl, {
      headers: { Accept: 'application/vnd.github+json' },
    });
    if (!response.ok) {
      if (response.status === 404) {
        useReleaseFallback('Direct download available · v0.1.3');
        return;
      }
      throw new Error(`GitHub returned ${response.status}`);
    }

    const release = await response.json();
    const installer = release.assets.find(asset =>
      /^Morpheus[ ._-]+Defense[ ._-]+Setup[ ._-]+.+\.exe$/i.test(asset.name),
    );
    if (!installer) {
      useReleaseFallback('Direct download available · v0.1.3');
      return;
    }

    headerDownload.href = installer.browser_download_url;
    downloadButton.href = installer.browser_download_url;
    headerDownloadLabel.textContent = 'Download .exe';
    const size = formatBytes(installer.size);
    const version = release.tag_name ? `Latest release ${release.tag_name}` : 'Latest Windows release';
    releaseStatus.textContent = `${version}${size ? ` · ${size}` : ''}`;
  } catch (error) {
    useReleaseFallback('Latest release check unavailable · direct download available');
    console.error('Unable to load the latest Morpheus Defense release:', error);
  }
}

loadLatestRelease();
