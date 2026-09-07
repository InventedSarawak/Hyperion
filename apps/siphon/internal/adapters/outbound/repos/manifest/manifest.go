// Package manifest parses dependency manifests into domain dependencies. It
// is pure: it takes bytes and returns domain types, with no knowledge of where
// the file came from. That keeps the awkward part of ingestion — real-world
// manifest syntax — testable without a network.
package manifest

import "github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"

// Parser reads one manifest format.
type Parser interface {
	// Path is the file this parser expects, e.g. "go.mod".
	Path() string
	// Parse maps the file's contents onto domain types.
	Parse(content []byte) (model.RepositorySnapshot, error)
}

// Parsers returns every manifest format siphon understands, in the order it
// tries them.
func Parsers() []Parser {
	return []Parser{GoMod{}, PackageJSON{}}
}
