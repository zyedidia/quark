package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func fatal(err ...interface{}) {
	fmt.Fprintln(os.Stderr, err...)
	os.Exit(1)
}

func run(command string, args ...string) {
	cmd := exec.Command(command, args...)
	log.Println(cmd)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if err != nil {
		fatal(err)
	}
}

func temp(dir string) string {
	tmp, err := os.CreateTemp(dir, ".quark.*.o")
	if err != nil {
		fatal(err)
	}
	tmp.Close()
	return tmp.Name()
}

func main() {
	var args, temps []string
	for i := 1; i < len(os.Args); i++ {
		if strings.HasSuffix(os.Args[i], ".o") {
			tmp := temp(os.TempDir())
			run("quark", os.Args[i], tmp)
			args = append(args, tmp)
			temps = append(temps, tmp)
		} else {
			args = append(args, os.Args[i])
		}
	}

	run(args[0], args[1:]...)

	for _, tmp := range temps {
		os.Remove(tmp)
	}
}
