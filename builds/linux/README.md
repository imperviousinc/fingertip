## Linux AppImage Package

Make sure both `hnsd` and `fingertip` binaries are in `./appdir/usr/bin/`.

Download / install [`linuxdeploy`](https://github.com/linuxdeploy/linuxdeploy).
Then build AppImage.

```sh
# download linuxdeploy
wget -c -nv "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage"
chmod +x linuxdeploy-x86_64.AppImage

# build
./linuxdeploy-x86_64.AppImage --appdir appdir --output appimage
```

AppImage will be in current directory.
