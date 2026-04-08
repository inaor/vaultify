package web

import "embed"

//go:embed *.html assets
var Content embed.FS
