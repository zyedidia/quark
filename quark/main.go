package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/erikgeiser/ar"
)

func isobj(name string) bool {
	return strings.HasSuffix(name, ".o") || strings.HasSuffix(name, ".lo")
}

func runcmd(c string, args ...string) error {
	cmd := exec.Command(c, args...)
	fmt.Println(cmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func run(module, in, out string) error {
	buf := &bytes.Buffer{}
	cmd := exec.Command(module, in, out)
	fmt.Println(cmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = buf
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("%w: %s", err, buf.String())
	}
	return nil
}

func quark(module, f string) (string, error) {
	out := f + ".quark.o"
	err := run(module, f, out)
	if err != nil {
		return "", err
	}
	return out, nil
}

var temps []string

func fatal(a ...interface{}) {
	rmtemps()
	fmt.Fprintln(os.Stderr, a...)
	os.Exit(1)
}

func rmtemps() {
	for _, t := range temps {
		os.Remove(t)
	}
}

func temp(f string) string {
	esc := strings.ReplaceAll(f, string(os.PathSeparator), "%")
	tmp := filepath.Join(os.TempDir(), esc)
	temps = append(temps, tmp)
	return tmp
}

type Object struct {
	name string
	data []byte
}

func main() {
	module := flag.String("module", "quark-module", "module")
	output := flag.String("o", "quark.a", "output library")

	flag.Parse()

	args := flag.Args()

	var objs []Object
	names := make(map[string]int)
	for _, a := range args {
		f, err := os.Open(a)
		if err != nil {
			fatal(err)
		}

		if isobj(a) {
			data, err := io.ReadAll(f)
			if err != nil {
				fatal(err)
			}
			objs = append(objs, Object{
				name: f.Name(),
				data: data,
			})
		} else if strings.HasSuffix(a, ".a") {
			r, err := ar.NewReader(f)
			if err != nil {
				fatal(err)
			}
			for hdr, err := r.Next(); err == nil; hdr, err = r.Next() {
				data := make([]byte, hdr.Size)
				_, err := r.Read(data)
				if err != nil {
					fatal(err)
				}
				name := hdr.Name
				if names[name] >= 1 {
					name = strconv.Itoa(names[name]) + name
				}
				names[name]++
				objs = append(objs, Object{
					name: name,
					data: data,
				})
			}
		}
		f.Close()
	}

	if len(objs) == 1 && isobj(*output) {
		f := temp(objs[0].name)
		err := os.WriteFile(f, objs[0].data, 0666)
		if err != nil {
			fatal(err)
		}
		out, err := quark(*module, f)
		if err != nil {
			fatal(err)
		}
		fmt.Println("rename", out, *output)
		err = os.Rename(out, *output)
		if err != nil {
			fatal(err)
		}

		// rmtemps()
		return
	}

	var qobjs []string
	for _, obj := range objs {
		if obj.name == "" {
			continue
		}

		f := temp(obj.name)
		err := os.WriteFile(f, obj.data, 0666)
		if err != nil {
			fatal(err)
		}
		out, err := quark(*module, f)
		if err != nil {
			fatal(err)
		}
		qobjs = append(qobjs, out)
	}

	ar := append([]string{"rcs", *output}, qobjs...)

	runcmd("ar", ar...)
	runcmd("ranlib", *output)

	rmtemps()
}
