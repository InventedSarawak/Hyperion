package manifest

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

var (
	pypiSeparators = regexp.MustCompile(`[-_.]+`)
	// pep508 is a requirement's name, optional extras, and the rest.
	pep508 = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$`)
)

// pypiName normalises a Python package name as PyPI does (PEP 503): "Flask",
// "flask" and "FLASK" are one project, as are "python_dateutil" and
// "python-dateutil". Advisories use the normalised form.
func pypiName(name string) string {
	return strings.ToLower(pypiSeparators.ReplaceAllString(strings.TrimSpace(name), "-"))
}

// parseRequirement reads one PEP 508 requirement — "fastapi==0.109.2",
// "uvicorn[standard]>=0.27; python_version>'3.8'" — into a normalised name and
// its version specifier. A direct URL reference names no version; a bare path
// or URL names no package.
func parseRequirement(s string) (name, spec string, ok bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = s[:i] // an environment marker
	}
	if at := strings.IndexByte(s, '@'); at > 0 {
		s = s[:at] // "name @ https://…": the version is whatever that is
	}
	if strings.Contains(s, "://") || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "/") {
		return "", "", false
	}
	m := pep508.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", "", false
	}
	spec = strings.Join(strings.Fields(strings.Trim(strings.TrimSpace(m[3]), "()")), "")
	return pypiName(m[1]), spec, true
}

// --- requirements.txt ---

// Requirements parses pip requirements files: requirements.txt and the
// variants projects split it into (requirements-dev.txt, requirements/base.txt).
type Requirements struct{}

// Name identifies the format.
func (Requirements) Name() string { return "requirements.txt" }

// Matches reports whether the file is a requirements file.
func (Requirements) Matches(filePath string) bool {
	b := strings.ToLower(path.Base(filePath))
	if !strings.HasSuffix(b, ".txt") {
		return false
	}
	return strings.HasPrefix(b, "requirements") || strings.HasSuffix(b, "-requirements.txt") ||
		path.Base(path.Dir(filePath)) == "requirements"
}

// Parse reads each requirement. Files named for development (-dev, -test)
// are recorded as indirect.
func (Requirements) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	direct := !devFile(filePath)
	file := filePath
	if !direct {
		file += " (dev)"
	}
	var snapshot model.RepositorySnapshot
	for _, line := range requirementLines(string(content)) {
		if name, spec, ok := parseRequirement(line); ok {
			snapshot.Dependencies = append(snapshot.Dependencies, dependency("pypi", name, spec, direct, file))
		}
	}
	return snapshot, nil
}

// requirementLines joins backslash continuations and drops comments, blank
// lines and pip options (-r, -e, --index-url, --hash …), which name no package.
func requirementLines(text string) []string {
	var (
		out []string
		cur strings.Builder
	)
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimRight(raw, " \t")
		if strings.HasSuffix(line, "\\") {
			cur.WriteString(strings.TrimSuffix(line, "\\") + " ")
			continue
		}
		cur.WriteString(line)
		l := cur.String()
		cur.Reset()
		if i := strings.Index(l, " #"); i >= 0 {
			l = l[:i]
		}
		if i := strings.Index(l, " --"); i >= 0 {
			l = l[:i] // per-requirement options, such as --hash
		}
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "-") {
			continue
		}
		out = append(out, l)
	}
	return out
}

// --- pyproject.toml ---

// Pyproject parses pyproject.toml: PEP 621 [project] dependencies, PEP 735
// dependency groups, and Poetry's [tool.poetry] tables.
type Pyproject struct{}

// Name identifies the format.
func (Pyproject) Name() string { return "pyproject.toml" }

// Matches reports whether the file is a pyproject.toml.
func (Pyproject) Matches(filePath string) bool { return path.Base(filePath) == "pyproject.toml" }

type pyprojectFile struct {
	Project struct {
		Name                 string              `toml:"name"`
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
	DependencyGroups map[string][]any `toml:"dependency-groups"`
	Tool             struct {
		Poetry struct {
			Name            string         `toml:"name"`
			Dependencies    map[string]any `toml:"dependencies"`
			DevDependencies map[string]any `toml:"dev-dependencies"`
			Group           map[string]struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

// Parse maps a pyproject.toml onto a snapshot.
func (Pyproject) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var f pyprojectFile
	if _, err := toml.Decode(string(content), &f); err != nil {
		return model.RepositorySnapshot{}, fmt.Errorf("manifest: parse %s: %w", filePath, err)
	}
	var snapshot model.RepositorySnapshot
	if name := firstNonEmpty(f.Project.Name, f.Tool.Poetry.Name); name != "" {
		snapshot.Publishes = valueobject.NewPackageRef("pypi", pypiName(name), "")
	}
	add := func(requirements []string, direct bool, file string) {
		for _, r := range requirements {
			if name, spec, ok := parseRequirement(r); ok {
				snapshot.Dependencies = append(snapshot.Dependencies, dependency("pypi", name, spec, direct, file))
			}
		}
	}
	add(f.Project.Dependencies, true, filePath)
	for _, extra := range sortedKeys(f.Project.OptionalDependencies) {
		add(f.Project.OptionalDependencies[extra], false, filePath+" (optional)")
	}
	for _, group := range sortedKeys(f.DependencyGroups) {
		var reqs []string
		for _, item := range f.DependencyGroups[group] {
			if s, ok := item.(string); ok {
				reqs = append(reqs, s)
			}
		}
		add(reqs, false, filePath+" (dev)")
	}
	snapshot.Dependencies = append(snapshot.Dependencies, poetryDependencies(f.Tool.Poetry.Dependencies, true, filePath)...)
	snapshot.Dependencies = append(snapshot.Dependencies, poetryDependencies(f.Tool.Poetry.DevDependencies, false, filePath+" (dev)")...)
	for _, group := range sortedKeys(f.Tool.Poetry.Group) {
		snapshot.Dependencies = append(snapshot.Dependencies,
			poetryDependencies(f.Tool.Poetry.Group[group].Dependencies, false, filePath+" (dev)")...)
	}
	return snapshot, nil
}

func poetryDependencies(entries map[string]any, direct bool, file string) []model.Dependency {
	var out []model.Dependency
	for _, name := range sortedKeys(entries) {
		if strings.EqualFold(name, "python") {
			continue // the interpreter, not a package
		}
		if version, ok := tableVersion(entries[name]); ok {
			out = append(out, dependency("pypi", pypiName(name), version, direct, file))
		}
	}
	return out
}

// tableVersion reads a constraint written as a string or as a table carrying
// one (Poetry, Pipfile). A dependency on a local path is the project's own
// code, not a package, and reports false.
func tableVersion(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		if t == "*" {
			return "", true
		}
		return t, true
	case map[string]any:
		if _, local := t["path"]; local {
			return "", false
		}
		s, _ := t["version"].(string)
		if s == "*" {
			s = ""
		}
		return s, true
	case []map[string]any:
		for _, m := range t {
			if s, ok := m["version"].(string); ok {
				return s, true
			}
		}
	case []any:
		for _, item := range t {
			if m, ok := item.(map[string]any); ok {
				if s, ok := m["version"].(string); ok {
					return s, true
				}
			}
		}
	}
	return "", true
}

// --- Pipfile ---

// Pipfile parses Pipenv's Pipfile.
type Pipfile struct{}

// Name identifies the format.
func (Pipfile) Name() string { return "Pipfile" }

// Matches reports whether the file is a Pipfile.
func (Pipfile) Matches(filePath string) bool { return path.Base(filePath) == "Pipfile" }

// Parse maps [packages] and [dev-packages].
func (Pipfile) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var f struct {
		Packages    map[string]any `toml:"packages"`
		DevPackages map[string]any `toml:"dev-packages"`
	}
	if _, err := toml.Decode(string(content), &f); err != nil {
		return model.RepositorySnapshot{}, fmt.Errorf("manifest: parse %s: %w", filePath, err)
	}
	var snapshot model.RepositorySnapshot
	snapshot.Dependencies = append(snapshot.Dependencies, poetryDependencies(f.Packages, true, filePath)...)
	snapshot.Dependencies = append(snapshot.Dependencies, poetryDependencies(f.DevPackages, false, filePath+" (dev)")...)
	return snapshot, nil
}
