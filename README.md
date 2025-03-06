# Fingertip

**Note:** This project is experimental use at your own risk.

Fingertip is a menubar app that runs a [lightweight decentralized resolver](https://github.com/handshake-org/hnsd) to resolve names from the [Handshake](https://handshake.org) root zone. It can also resolve names from external namespaces such as the Ethereum Name System. Fingertip integrates with [sane](https://github.com/randomlogin/sane) to provide TLS support without relying on a centralized certificate authority. 

For handshake domains fingertip can be thought as a user-friendly wrapper of SANE, it uses hardcoded community-hosted external proof services, and DNS over HTTPS for name resolution. An advanced user is welcome to use [sane](https://github.com/randomlogin/sane) directly.


<img width="600" src="https://user-images.githubusercontent.com/41967894/127166063-fedf072c-fa5e-45e3-acac-bfb46f256831.png" />

## Backends

Currently there are two available backends: [letsdane](https://github.com/buffrr/letsdane) and [sane](https://github.com/randomlogin/sane). It's possible to switch between them in the tray options.

Letsdane runs with an [hnsd](https://github.com/handshake-org/hnsd) instance which resolves handshake domains and verifies DANE records.

SANE uses [Stateless DANE](https://github.com/handshake-org/HIPs/blob/master/HIP-0017.md) and runs hnsd once a day (for about 10 seconds) to download the latest tree roots and verify certificate proofs against them.

#### SANE's external services

To comply with SANE, the website hosted at a handshake domain has to provide relevant proof data. Proof allows to verify that a TLSA record, which contains information about certificate that should be used by a domain name, corresponds to a recent block in a blockchain. 

To keep this information up-to-date, the website owner has to periodically update (re-generate) certificate. Updating certificate might be cumbersome for some of the site owners, so to address this problem there are 'external services' which construct the needed proofs, thus allowing the domain owner not to update the certificate. Though if the certificate has all the needed information, the request to the external service is not done at all.

External services cannot provide false information (it's impossible to provide a false proof), but they can be down or timeout. In the current default settings of fingertip there are [3 hardcoded community-hosted external services](https://github.com/randomlogin/sane?tab=readme-ov-file#external-service).

To sum up:
- Letsdane: takes more resources, but completely independent
- SANE: more lightweight, but makes a request for non-SANE-compliant certificates.

## Install

You can use a pre-built binary from releases or build your own from source.

To run pre-build AppImage on Linux you might need `libfuse`:

```
apt install libfuse2`
```

## Configuration
You can set these as environment variables prefixed with `FINGERTIP_` or store it in the app config directory as `fingertip.env`

```
# sane proxy address
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

Go 1.21+ is required.

### MacOS

```
$ brew install dylibbundler git automake autoconf libtool unbound getdns
$ git clone https://github.com/randomlogin/fingertip
$ cd fingertip && ./builds/macos/build.sh
```

For development, you can run fingertip from the following path:
```
$ ./builds/macos/Fingertip.app/Contents/MacOS/fingertip
```
        
Configure your IDE to output to this directory or continue to use `build.sh` when making changes (it will only build hnsd once).


### Linux

Follow [hnsd](https://github.com/handshake-org/hnsd) build instructions for Linux. Copy hnsd binary into the `fingertip/builds/linux/appdir/usr/bin` directory.

```
$ go build -trimpath -o ./builds/linux/appdir/usr/bin/
```

To create an AppImage run the following script: 

```
bash builds/linux/create_appimage.sh 
```

### Windows

Due to the [difference](https://github.com/handshake-org/hnsd/issues/128) in hnsd behaviour on Windows and other platforms (and overall complexity of building for windows), stateless DANE is not supported on Windows.
The version from the [v0.0.3 release](https://github.com/imperviousinc/fingertip/releases/tag/v0.0.3) should be used for usual DANE.


## Credits
Fingertip uses [hnsd](https://github.com/handshake-org/hnsd) a lightweight Handshake resolver, [sane](https://github.com/randomlogin/sane) and [getdns](https://getdnsapi.net/) for TLS support and [go-ethereum](https://github.com/ethereum/go-ethereum) for .eth and Ethereum [HIP-5](https://github.com/handshake-org/HIPs/blob/master/HIP-0005.md) lookups.

The name "fingertip" was stolen from [@pinheadmz](https://github.com/pinheadmz)
