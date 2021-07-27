//+build windows

package main

import (
	"embed"
	_ "embed"
	"io/fs"
	"io/ioutil"
	"os"
	"path"
)

//go:embed builds/windows/*
var dnsProcDist embed.FS

func createProcPath(configDir string) (string, error) {
	procDir := path.Join(configDir, "dns-proc")

	if _, err := os.Stat(procDir); err != nil {
		if err := os.Mkdir(procDir, 0700); err != nil {
			return "", err
		}

		err := fs.WalkDir(dnsProcDist, ".",
			func(fpath string, d fs.DirEntry, err error) error {
				return copyFile(fpath, procDir, err)
			})

		if err != nil {
			return "", err
		}
	}

	return procDir, nil
}

func copyFile(fpath, procDir string, err error) error {
	if err != nil {
		return err
	}

	f, err := dnsProcDist.Open(fpath)
	if err != nil {
		return err
	}
	stat, err := f.Stat()
	if err != nil {
		return err
	}

	if stat.IsDir() {
		// no support for dirs
		return nil
	}

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	fOut, err := os.OpenFile(path.Join(procDir, stat.Name()),
		os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fOut.Write(data)
	return err
}
