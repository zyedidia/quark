package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func run(cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	fmt.Println(c)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func quarkify(path, module string) string {
	name := filepath.Base(path)

	target := filepath.Join(os.TempDir(), name)
	run("quark", "-module", module, "-o", target, path)

	return target
}

func findlib(name string, search []string) (string, bool) {
	for _, dir := range search {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, ent := range ents {
			if ent.Name() == name && !ent.IsDir() {
				return filepath.Join(dir, ent.Name()), true
			}
		}
	}
	return "", false
}

func main() {
	args := os.Args[1:]

	var ldargs []string
	var search []string

	module := ""

	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "-L"):
			search = append(search, arg[len("-L"):])
		case strings.HasPrefix(arg, "--quark-module="):
			// TODO: expand home directory
			module = arg[len("--quark-module="):]
		}
	}

	if module == "" {
		log.Fatal("no quark module")
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "--quark-module="):
			continue
		case strings.HasSuffix(arg, ".a"), strings.HasSuffix(arg, ".o"):
			ldargs = append(ldargs, quarkify(arg, module))
		case strings.HasPrefix(arg, "-l"):
			name := "lib" + arg[len("-l"):] + ".a"
			lib, ok := findlib(name, search)
			if ok {
				ldargs = append(ldargs, quarkify(lib, module))
			}
		default:
			ldargs = append(ldargs, arg)
		}
	}

	run("ld", ldargs...)
}
