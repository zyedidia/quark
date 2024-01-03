package main

import (
	"crypto/sha256"
	"encoding/gob"
	"os"
	"path/filepath"

	"github.com/segmentio/fasthash/fnv1a"
)

type Cache struct {
	// key is a short hash of the input
	Entries map[uint64][]Entry

	file string
}

type Entry struct {
	Module [sha256.Size]byte
	Input  [sha256.Size]byte

	Data []byte
}

func LoadCache(file string) (*Cache, error) {
	f, err := os.Open(file)
	if err != nil {
		return &Cache{
			Entries: make(map[uint64][]Entry),
			file:    file,
		}, nil
	}
	defer f.Close()
	dec := gob.NewDecoder(f)
	var c Cache
	err = dec.Decode(&c)
	if err != nil {
		return nil, err
	}
	c.file = file
	return &c, nil
}

func (c *Cache) Lookup(file, module string) ([]byte, bool) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, false
	}
	hash := fnv1a.HashBytes64(data)
	ents, ok := c.Entries[hash]
	if !ok {
		return nil, false
	}
	moduleData, err := os.ReadFile(module)
	if err != nil {
		return nil, false
	}
	dataHash := sha256.Sum256(data)
	moduleHash := sha256.Sum256(moduleData)
	for _, ent := range ents {
		if dataHash == ent.Input && moduleHash == ent.Module {
			return ent.Data, true
		}
	}
	return nil, false
}

func (c *Cache) Insert(file, module string, data []byte) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	hash := fnv1a.HashBytes64(data)
	moduleData, err := os.ReadFile(module)
	if err != nil {
		return err
	}
	dataHash := sha256.Sum256(data)
	moduleHash := sha256.Sum256(moduleData)
	c.Entries[hash] = append(c.Entries[hash], Entry{
		Module: moduleHash,
		Input:  dataHash,
		Data:   data,
	})
	return nil
}

func (c *Cache) Quarkify(path, module string) (string, error) {
	name := filepath.Base(path)
	target := filepath.Join(os.TempDir(), name)

	if b, ok := c.Lookup(path, module); ok {
		f, err := os.Create(target)
		if err != nil {
			return "", err
		}
		_, err = f.Write(b)
		f.Close()
		return f.Name(), err
	} else {
		run("quark", "-module", module, "-o", target, path)

		data, err := os.ReadFile(target)
		if err != nil {
			return "", err
		}
		err = c.Insert(path, module, data)
		if err != nil {
			return "", err
		}
	}
	return target, nil
}

func (c *Cache) Save() error {
	f, err := os.Create(c.file)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := gob.NewEncoder(f)
	return enc.Encode(c)
}
