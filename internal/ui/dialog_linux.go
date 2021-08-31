//+build linux

package ui

import (
	"os/exec"
)

var tool string

func init() {
	for _, tool = range []string{"qarma", "zenity", "matedialog"} {
		path, _ := exec.LookPath(tool)
		if path != "" {
			return
		}
	}
	tool = "zenity"
}

func run(args []string) ([]byte, error) {
	return exec.Command(tool, args...).Output()
}

func ShowErrorDlg(err string) {
	run([]string{"--no-wrap", "--error", "--text", err})
}

func ShowYesNoDlg(msg string) bool {
	_, err := run([]string{"--no-wrap", "--question", "--text", msg})
	return err == nil
}
