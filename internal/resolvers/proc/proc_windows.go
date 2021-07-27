// +build windows

package proc

import (
	"syscall"
)

var processAttributes = &syscall.SysProcAttr{HideWindow: true}
var processExtension = ".exe"
