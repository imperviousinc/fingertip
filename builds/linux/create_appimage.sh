#!/bin/bash
# make sure path is correct
# so that pwd points to main repo directory
[[ -e builds/linux/create_appimage.sh ]] || { echo >&2 "Please cd into fingertip repo before running this script."; exit 1; }



# Create AppRun script
cat > linux/appdir/AppRun <<'EOL'
#!/bin/sh
HERE="$(dirname "$(readlink -f "${0}")")"
export PATH="${HERE}/usr/bin:$PATH"
exec fingertip "$@"
EOL
chmod +x builds/linux/appdir/AppRun

# Download linuxdeployqt if not already downloaded
if [ ! -f ./linuxdeployqt-continuous-x86_64.AppImage ]; then
  wget https://github.com/probonopd/linuxdeployqt/releases/download/continuous/linuxdeployqt-continuous-x86_64.AppImage
  chmod +x linuxdeployqt-continuous-x86_64.AppImage
fi

# Run linuxdeployqt to create the AppImage
./linuxdeployqt-continuous-x86_64.AppImage builds/linux/appdir/usr/bin/hnsd -appimage -unsupported-allow-new-glibc -verbose=3
./linuxdeployqt-continuous-x86_64.AppImage builds/linux/appdir/usr/bin/fingertip -appimage -always-overwrite -unsupported-allow-new-glibc -verbose=3
