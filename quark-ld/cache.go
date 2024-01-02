package main

import (
	"crypto/sha256"
	"os"

	"github.com/segmentio/fasthash/fnv1a"
)

type Cache struct {
	// key is a short hash of the input
	Entries map[uint64][]Entry
}

type Entry struct {
	Module [sha256.Size]byte
	Input  [sha256.Size]byte

	File string
}

func LoadCache(dir string) (*Cache, error) {
	return nil, nil
}

func (c *Cache) Lookup(file, module string) (string, bool) {
	data, err := os.ReadFile(file)
	if err != nil {
		return "", false
	}
	hash := fnv1a.HashBytes64(data)
	ents, ok := c.Entries[hash]
	if !ok {
		return "", false
	}
	moduleData, err := os.ReadFile(module)
	if err != nil {
		return "", false
	}
	dataHash := sha256.Sum256(data)
	moduleHash := sha256.Sum256(moduleData)
	for _, ent := range ents {
		if dataHash == ent.Input && moduleHash == ent.Module {
			return ent.File, true
		}
	}
	return "", false
}

func (c *Cache) Insert(file, module string) error {
	return nil
}

func (c *Cache) Save() error {
	return nil
}
