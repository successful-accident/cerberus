// Package cerberus holds the files embedded in the binary: the distro catalog
// and the signing keys it pins.
package cerberus

import "embed"

// CatalogFS holds catalog/*.yaml and catalog/keys/*.asc.
//
//go:embed catalog
var CatalogFS embed.FS
