const fs = require('node:fs');
const path = require('node:path');
const { app, BrowserWindow, nativeImage } = require('electron');

const root = path.resolve(__dirname, '..');
const svgPath = path.join(root, 'desktop', 'app-icon.svg');
const pngPath = path.join(root, 'desktop', 'tray-icon.png');
const icoPath = path.join(root, 'desktop', 'tray-icon.ico');
const iconSizes = [16, 24, 32, 48, 64, 128, 256];

function createIco(images) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(images.length, 4);

  let offset = header.length + images.length * 16;
  const directory = [];
  for (const { size, data } of images) {
    const entry = Buffer.alloc(16);
    entry.writeUInt8(size === 256 ? 0 : size, 0);
    entry.writeUInt8(size === 256 ? 0 : size, 1);
    entry.writeUInt8(0, 2);
    entry.writeUInt8(0, 3);
    entry.writeUInt16LE(1, 4);
    entry.writeUInt16LE(32, 6);
    entry.writeUInt32LE(data.length, 8);
    entry.writeUInt32LE(offset, 12);
    directory.push(entry);
    offset += data.length;
  }
  return Buffer.concat([header, ...directory, ...images.map(image => image.data)]);
}

app.whenReady().then(async () => {
  const svg = fs.readFileSync(svgPath);
  const window = new BrowserWindow({
    show: false,
    webPreferences: { offscreen: true },
  });
  const svgDataUrl = `data:image/svg+xml;base64,${svg.toString('base64')}`;
  const html = `<img src="${svgDataUrl}" alt="">`;
  await window.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`);
  const pngDataUrl = await window.webContents.executeJavaScript(`(() => {
    const image = document.querySelector('img');
    const canvas = document.createElement('canvas');
    canvas.width = 256;
    canvas.height = 256;
    canvas.getContext('2d').drawImage(image, 0, 0, 256, 256);
    return canvas.toDataURL('image/png');
  })()`);
  window.destroy();
  const image = nativeImage.createFromDataURL(pngDataUrl);
  if (image.isEmpty()) throw new Error(`Could not render the Morpheus icon: ${svgPath}`);

  const images = iconSizes.map(size => ({
    size,
    data: image.resize({ width: size, height: size, quality: 'best' }).toPNG(),
  }));
  fs.writeFileSync(pngPath, images.find(item => item.size === 256).data);
  fs.writeFileSync(icoPath, createIco(images));
  app.quit();
}).catch(error => {
  console.error(error);
  app.exit(1);
});
