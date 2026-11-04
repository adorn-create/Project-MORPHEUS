const repository = 'adorn-create/Project-MORPHEUS';
const releaseUrl = `https://api.github.com/repos/${repository}/releases/latest`;
const releasesPageUrl = `https://github.com/${repository}/releases/latest`;
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
  headerDownload.href = releasesPageUrl;
  headerDownloadLabel.textContent = 'View latest release';
  downloadButton.href = releasesPageUrl;
  downloadLabel.textContent = 'View latest Windows release';
  releaseStatus.textContent = message;
}

async function loadLatestRelease() {
  try {
    const response = await fetch(releaseUrl, {
      headers: { Accept: 'application/vnd.github+json' },
    });
    if (!response.ok) {
      if (response.status === 404) {
        useReleaseFallback('Latest installer: view the published GitHub release.');
        return;
      }
      throw new Error(`GitHub returned ${response.status}`);
    }

    const release = await response.json();
    const installer = release.assets.find(asset =>
      /^Morpheus[ ._-]+Defense[ ._-]+Setup[ ._-]+.+\.exe$/i.test(asset.name),
    );
    if (!installer) {
      useReleaseFallback('No Windows installer found in the latest release. View release assets.');
      return;
    }

    headerDownload.href = installer.browser_download_url;
    downloadButton.href = installer.browser_download_url;
    headerDownloadLabel.textContent = 'Download .exe';
    downloadLabel.textContent = 'Download Windows App (.exe)';
    const size = formatBytes(installer.size);
    const version = release.tag_name ? `Latest release ${release.tag_name}` : 'Latest Windows release';
    releaseStatus.textContent = `${version}${size ? ` · ${size}` : ''}`;
  } catch (error) {
    useReleaseFallback('View the latest installer and release notes on GitHub.');
    console.error('Unable to load the latest Morpheus Defense release:', error);
  }
}

loadLatestRelease();
