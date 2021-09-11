# Fingertip

**Note:** This project is experimental use at your own risk.

Fingertip is a menubar app that runs a [lightweight decentralized resolver](https://github.com/handshake-org/hnsd) to resolve names from the [Handshake](https://handshake.org) root zone. It can also resolve names from external namespaces such as the Ethereum Name System. Fingertip integrates with [letsdane](https://github.com/buffrr/letsdane) to provide TLS support without relying on a centralized certificate authority. 


<img width="600" src="https://user-images.githubusercontent.com/41967894/127166063-fedf072c-fa5e-45e3-acac-bfb46f256831.png" />

## Install

You can use a pre-built binary from releases or build your own from source.

## Configuration
You can set these as environment variables prefixed with `FINGERTIP_` or store it in the app config directory as `fingertip.env`

```
# letsdane proxy address
PROXY_ADDRESS=127.0.0.1:9590
# hnsd root server address
ROOT_ADDRESS=127.0.0.1:9591
# hnsd recursive resolver address
RECURSIVE_ADDRESS=127.0.0.1:9592
# Connect your own Ethereum full node/or blockchain provider such as Infura
#ETHEREUM_ENDPOINT=/home/user/.ethereum/geth.ipc or
#ETHEREUM_ENDPOINT=https://mainnet.infura.io/v3/YOUR-PROJECT-ID
```

## Build from source

Go 1.16+ is required.

```
$ git clone https://github.com/buffrr/fingertip
```

### MacOS

```
$ brew install dylibbundler git automake autoconf libtool unbound
$ git clone https://github.com/imperviousinc/fingertip
$ cd fingertip && ./builds/macos/build.sh
```

For development, you can run fingertip from the following path:
```
$ ./builds/macos/Fingertip.app/Contents/MacOS/fingertip
```
        
Configure your IDE to output to this directory or continue to use `build.sh` when making changes (it will only build hnsd once).

### Windows

Follow [hnsd](https://github.com/handshake-org/hnsd) build instructions for windows. Copy hnsd.exe binary and its dependencies (libcrypto, libssl and libunbound dlls) into the `fingertip/builds/windows` directory.
You no longer need to use MSYS shell.

```
$ choco install mingw
$ go build -trimpath -o ./builds/windows/  -ldflags "-H windowsgui"
```

### Linux

Follow [hnsd](https://github.com/handshake-org/hnsd) build instructions for Linux. Copy hnsd binary into the `fingertip/builds/linux/appdir/usr/bin` directory.

```
$ go build -trimpath -o ./builds/linux/appdir/usr/bin/
```


## Credits
Fingertip uses [hnsd](https://github.com/handshake-org/hnsd) a lightweight Handshake resolver, [letsdane](https://github.com/buffrr/letsdane) for TLS support and [go-ethereum](https://github.com/ethereum/go-ethereum) for .eth and Ethereum [HIP-5](https://github.com/handshake-org/HIPs/blob/master/HIP-0005.md) lookups.

The name "fingertip" was stolen from [@pinheadmz](https://github.com/pinheadmz)
