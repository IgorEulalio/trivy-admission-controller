package scan

import "os/exec"

type Runner interface {
	Run(name string, arg ...string) *exec.Cmd
	RunCommand(cmd *exec.Cmd) error
}

type DefaultCommandRunner struct{}

func (dcr DefaultCommandRunner) Run(name string, arg ...string) *exec.Cmd {
	return exec.Command(name, arg...)
}

func (dcr DefaultCommandRunner) RunCommand(cmd *exec.Cmd) error {
	return cmd.Run()
}
