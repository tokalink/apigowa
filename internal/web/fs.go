package web

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
)

//go:embed templates/*
var Content embed.FS

func GetFileSystem() http.FileSystem {
	fsys, err := fs.Sub(Content, "templates")
	if err != nil {
		panic(err)
	}
	return http.FS(fsys)
}

func GetIndex(version string) ([]byte, error) {
	data, err := Content.ReadFile("templates/index.html")
	if err != nil {
		return nil, err
	}
	return bytes.Replace(data, []byte("{{VERSION}}"), []byte(version), -1), nil
}
