//+build !linux

package ui

import "github.com/sqweek/dialog"

func ShowErrorDlg(err string) {
	dialog.Message("%s", err).Title("Error").Error()
}

func ShowYesNoDlg(msg string) bool {
	return dialog.Message("%s", msg).Title("Confirmation").YesNo()
}
