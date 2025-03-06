#!/bin/bash

# make sure path is correct
# so that pwd points to main repo directory
[[ -e builds/macos/build.sh ]] || { echo >&2 "Please cd into fingertip repo before running this script."; exit 1; }

min_macos_version="10.13"
cflags="-mmacosx-version-min="${min_macos_version}
working_dir=$(pwd)
bundle_path="${working_dir}/builds/macos/Fingertip.app/Contents"
hnsd_path=${bundle_path}/MacOS/hnsd
fingertip_path=${bundle_path}/MacOS/fingertip
lib_dir=${bundle_path}/Frameworks

if [ ! -e "$hnsd_path" ]; then

echo "Cloning hnsd ..."
tmp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t 'fingertip_hnsd')
git clone https://github.com/handshake-org/hnsd "$tmp_dir"
cd "$tmp_dir" || exit

echo "Building hnsd ..."
./autogen.sh && ./configure --with-unbound=$(brew --prefix) 
make CFLAGS=$cflags -j 10
cp "${tmp_dir}/hnsd" "$hnsd_path"

cd "$working_dir" || exit

# bundle libs
dylibbundler -od -b -x "$hnsd_path" -d "$lib_dir" -p @executable_path/../Frameworks/

fi

# build fingertip
BREW_PREFIX=$(brew --prefix getdns)
CGO_CFLAGS="-I$BREW_PREFIX/include"
CGO_LDFLAGS="-L$BREW_PREFIX/lib -lgetdns"
CGO_CFLAGS="$cflags $CGO_CFLAGS" CGO_LDFLAGS="$cflags $CGO_LDFLAGS" go build -trimpath -o "$fingertip_path"

# bundle libs
dylibbundler -od -b -x "$fingertip_path" -d "$lib_dir" -p @executable_path/../Frameworks/

get_min_version() {
   otool -l $1 | grep LC_VERSION_MIN_MACOSX  -A3 | grep version | xargs | sed s/version// | xargs
}

check_min_version() {
  min=$(get_min_version "$1")
  name=$(basename "$1")
  if [ "$min" != "$min_macos_version" ] ; then
    echo "Warning: ${name} got min version = ${min}, want $min_macos_version"
  fi
}

check_min_version "$fingertip_path"
check_min_version "$hnsd_path"

for file in "${lib_dir}"/*
do
  check_min_version "$file"
done
