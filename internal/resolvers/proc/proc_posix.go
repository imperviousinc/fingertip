// +build !windows

package proc

import (
	"syscall"
)

var processAttributes = &syscall.SysProcAttr{}
var processExtension = ""
