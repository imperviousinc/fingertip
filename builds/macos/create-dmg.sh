if [ ! -d Fingertip.app ]; then
	echo "Fingertip.app not found, try to rebuild"
	exit 1
fi
mkdir dmgcontents
cp -r Fingertip.app dmgcontents/
ln -s /Applications dmgcontents/Applications
hdiutil create -volname "fingertip" -srcfolder dmgcontents -ov -format UDZO fingertip.dmg
rm -r dmgcontents
