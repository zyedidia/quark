package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/adrg/xdg"
)

func run(cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	fmt.Println(c)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
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

	cache, err := LoadCache(filepath.Join(xdg.CacheHome, "quark", "objcache"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("loaded cache", cache.file)

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
			f, err := cache.Quarkify(arg, module)
			if err != nil {
				log.Fatal(err)
			}
			ldargs = append(ldargs, f)
		case strings.HasPrefix(arg, "-l"):
			name := "lib" + arg[len("-l"):] + ".a"
			lib, ok := findlib(name, search)
			if ok {
				f, err := cache.Quarkify(lib, module)
				if err != nil {
					log.Fatal(err)
				}
				ldargs = append(ldargs, f)
			}
		default:
			ldargs = append(ldargs, arg)
		}
	}

	err = run("gold", ldargs...)
	if err != nil {
		log.Fatal(err)
	}

	err = cache.Save()
	if err != nil {
		log.Fatal(err)
	}
}
