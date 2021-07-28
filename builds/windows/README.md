## Windows MSI Package

If creating a new update, set version in `manifest.xml`

Create .syso file before building the binary since Go reads .syso files in the same directory as `go build` command.

```
$ rsrc -arch amd64 -ico fingertip.ico -manifest manifest.xml -o ../../rsrc.syso
```

`fingertip.exe` should now be in this directory compiled with .syso file. Build the package

```
$ go-msi make --msi fingertip.msi --version 0.0.1 --src templates --arch amd64
```