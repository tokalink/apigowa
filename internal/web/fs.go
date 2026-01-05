package web

import (
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

func GetIndex() ([]byte, error) {
	return Content.ReadFile("templates/index.html")
}
