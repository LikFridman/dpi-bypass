package main

import (
	"os/exec"
	"syscall"
)

// childSetup - дочерний процесс (Xray) умирает вместе с этим процессом, даже если его убили
func childSetup(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
