package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/erikgeiser/ar"
)

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

	flag.Parse()

	args := flag.Args()

	var objs []Object
	for _, a := range args {
		f, err := os.Open(a)
		if err != nil {
			fatal(err)
		}

		if strings.HasSuffix(a, ".o") {
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
				objs = append(objs, Object{
					name: hdr.Name,
					data: data,
				})
			}
		}
		f.Close()
	}

	buf := &bytes.Buffer{}
	w := ar.NewWriter(buf)

	for _, obj := range objs {
		if obj.name == "" {
			continue
		}

		f := temp(obj.name)
		os.WriteFile(f, obj.data, 0666)
		out, err := quark(*module, f)
		if err != nil {
			fatal(err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			fatal(err)
		}
		hdr, err := ar.NewHeaderFromFile(out)
		if err != nil {
			fatal(err)
		}
		hdr.Name = obj.name
		w.WriteHeader(hdr)
		w.Write(data)
	}
	w.Close()

	os.WriteFile("out.a", buf.Bytes(), 0666)
}
