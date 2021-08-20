## Linux AppImage Package

Make sure both `hnsd` and `fingertip` binaries are in `./appdir/usr/bin/`.

Download / install [`linuxdeployqt`](https://github.com/probonopd/linuxdeployqt). Then build AppImage.

```sh
# download linuxdeployqt
wget -c -nv "https://github.com/probonopd/linuxdeployqt/releases/download/continuous/linuxdeployqt-continuous-x86_64.AppImage"
chmod +x linuxdeployqt-continuous-x86_64.AppImage

# build
./linuxdeployqt-continuous-x86_64.AppImage appdir/usr/share/applications/fingertip.desktop -appimage -always-overwrite
```

AppImage will be in current directory.

> **Note:** Builds depend on the glibc in your system. This build will only work on systems with glibc >= current version. This is why the CI builds in an old Ubuntu 18.04 container. [More info](https://github.com/probonopd/linuxdeployqt#a-note-on-binary-compatibility)

> `linuxdeployqt` may throw an error if glibc is too new (yes, new). Add `-unsupported-allow-new-glibc` to bypass it.
