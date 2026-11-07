//go:build !linux

package main

import "os/exec"

func childSetup(c *exec.Cmd) {}
