package manifest

import (
	"encoding/xml"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// Java packages are named "groupId:artifactId", which is how Maven advisories
// name them too.

// --- pom.xml ---

// Pom parses a Maven project file.
type Pom struct{}

// Name identifies the format.
func (Pom) Name() string { return "pom.xml" }

// Matches reports whether the file is a pom.xml.
func (Pom) Matches(filePath string) bool { return path.Base(filePath) == "pom.xml" }

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

type pomProject struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Parent     struct {
		GroupID string `xml:"groupId"`
		Version string `xml:"version"`
	} `xml:"parent"`
	Properties struct {
		Entries []struct {
			XMLName xml.Name
			Value   string `xml:",chardata"`
		} `xml:",any"`
	} `xml:"properties"`
	Managed      []pomDependency `xml:"dependencyManagement>dependencies>dependency"`
	Dependencies []pomDependency `xml:"dependencies>dependency"`
}

var pomProperty = regexp.MustCompile(`\$\{([^}]+)\}`)

// Parse maps a pom onto a snapshot. ${property} references are resolved from
// the file's own properties; one defined in a parent pom this scan cannot see
// leaves the version unknown rather than wrong. Test and provided scopes are
// recorded as indirect.
func (Pom) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var p pomProject
	if err := xml.Unmarshal(content, &p); err != nil {
		return model.RepositorySnapshot{}, fmt.Errorf("manifest: parse %s: %w", filePath, err)
	}
	group := firstNonEmpty(p.GroupID, p.Parent.GroupID)
	version := firstNonEmpty(p.Version, p.Parent.Version)
	props := map[string]string{
		"project.version": version, "pom.version": version, "version": version,
		"project.groupId": group, "project.parent.version": p.Parent.Version,
	}
	for _, e := range p.Properties.Entries {
		props[e.XMLName.Local] = strings.TrimSpace(e.Value)
	}
	resolve := func(s string) string {
		s = strings.TrimSpace(s)
		for i := 0; i < 5 && strings.Contains(s, "${"); i++ { // properties may refer to properties
			s = pomProperty.ReplaceAllStringFunc(s, func(m string) string {
				if v, ok := props[m[2:len(m)-1]]; ok {
					return v
				}
				return m
			})
		}
		if strings.Contains(s, "${") {
			return ""
		}
		return s
	}
	managed := map[string]string{}
	for _, d := range p.Managed {
		managed[resolve(d.GroupID)+":"+resolve(d.ArtifactID)] = resolve(d.Version)
	}

	var snapshot model.RepositorySnapshot
	if p.ArtifactID != "" && group != "" {
		snapshot.Publishes = valueobject.NewPackageRef("maven", resolve(group)+":"+resolve(p.ArtifactID), "")
	}
	for _, d := range p.Dependencies {
		g, a := resolve(d.GroupID), resolve(d.ArtifactID)
		if g == "" || a == "" {
			continue
		}
		name := g + ":" + a
		v := resolve(d.Version)
		if v == "" {
			v = managed[name]
		}
		scope := strings.ToLower(strings.TrimSpace(d.Scope))
		direct := scope != "test" && scope != "provided"
		file := filePath
		if !direct {
			file += " (" + scope + ")"
		}
		snapshot.Dependencies = append(snapshot.Dependencies, dependency("maven", name, v, direct, file))
	}
	return snapshot, nil
}

// --- build.gradle / build.gradle.kts ---

// Gradle reads the dependencies a Gradle build script declares, in both the
// Groovy and the Kotlin DSL — including Android apps. A build script is a
// program, so only the declarative forms are read: "group:artifact:version"
// strings and group/name/version maps. Versions held in variables are left
// unknown rather than guessed.
type Gradle struct{}

// Name identifies the format.
func (Gradle) Name() string { return "build.gradle" }

// Matches reports whether the file is a Gradle build script.
func (Gradle) Matches(filePath string) bool {
	b := path.Base(filePath)
	return b == "build.gradle" || b == "build.gradle.kts"
}

var (
	gradleCoordinate = regexp.MustCompile(`(?m)^[ \t]*(\w+)[ \t]*\(?[ \t]*(?:(?:enforced)?[Pp]latform[ \t]*\([ \t]*)?["']([^"'\s:$]+):([^"'\s:$]+)(?::([^"'\s:@]*))?[^"'\n]*["']`)
	gradleMap        = regexp.MustCompile(`(?m)^[ \t]*(\w+)[ \t]*\(?[ \t]*group[ \t]*[:=][ \t]*["']([^"']+)["'][ \t]*,[ \t]*name[ \t]*[:=][ \t]*["']([^"']+)["'](?:[ \t]*,[ \t]*version[ \t]*[:=][ \t]*["']([^"']+)["'])?`)
	gradleConfig     = regexp.MustCompile(`(?i)(implementation|api|compile|runtime|kapt|ksp|annotationprocessor|classpath|developmentonly)`)
)

// Parse maps a build script onto a snapshot. Test configurations and the
// buildscript classpath are recorded as indirect.
func (Gradle) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	text := string(content)
	var snapshot model.RepositorySnapshot
	seen := map[string]bool{}
	add := func(config, group, artifact, version string) {
		if !gradleConfig.MatchString(config) {
			return
		}
		name := group + ":" + artifact
		if seen[config+" "+name] {
			return
		}
		seen[config+" "+name] = true
		if strings.Contains(version, "$") {
			version = "" // a variable this scan cannot resolve
		}
		lower := strings.ToLower(config)
		direct := !strings.Contains(lower, "test") && lower != "classpath"
		file := filePath
		if !direct {
			file += " (" + config + ")"
		}
		snapshot.Dependencies = append(snapshot.Dependencies, dependency("maven", name, version, direct, file))
	}
	for _, m := range gradleCoordinate.FindAllStringSubmatch(text, -1) {
		add(m[1], m[2], m[3], m[4])
	}
	for _, m := range gradleMap.FindAllStringSubmatch(text, -1) {
		add(m[1], m[2], m[3], m[4])
	}
	return snapshot, nil
}

// --- gradle/libs.versions.toml ---

// VersionCatalog parses a Gradle version catalog, where modern builds
// (Android's templates included) keep their library versions.
type VersionCatalog struct{}

// Name identifies the format.
func (VersionCatalog) Name() string { return "libs.versions.toml" }

// Matches reports whether the file is a version catalog.
func (VersionCatalog) Matches(filePath string) bool {
	return strings.HasSuffix(path.Base(filePath), ".versions.toml")
}

// Parse maps [libraries] onto dependencies, resolving version.ref.
func (VersionCatalog) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var c struct {
		Versions  map[string]any `toml:"versions"`
		Libraries map[string]any `toml:"libraries"`
	}
	if _, err := toml.Decode(string(content), &c); err != nil {
		return model.RepositorySnapshot{}, fmt.Errorf("manifest: parse %s: %w", filePath, err)
	}
	var snapshot model.RepositorySnapshot
	for _, alias := range sortedKeys(c.Libraries) {
		if name, version := catalogLibrary(c.Libraries[alias], c.Versions); name != "" {
			snapshot.Dependencies = append(snapshot.Dependencies, dependency("maven", name, version, true, filePath))
		}
	}
	return snapshot, nil
}

func catalogLibrary(v any, versions map[string]any) (name, version string) {
	switch t := v.(type) {
	case string:
		parts := strings.Split(t, ":")
		if len(parts) < 2 {
			return "", ""
		}
		if len(parts) > 2 {
			version = parts[2]
		}
		return parts[0] + ":" + parts[1], version
	case map[string]any:
		if module, ok := t["module"].(string); ok {
			name = module
		} else {
			g, _ := t["group"].(string)
			n, _ := t["name"].(string)
			if g == "" || n == "" {
				return "", ""
			}
			name = g + ":" + n
		}
		return name, catalogVersion(t["version"], versions)
	}
	return "", ""
}

func catalogVersion(v any, versions map[string]any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		if ref, ok := t["ref"].(string); ok && versions != nil {
			return catalogVersion(versions[ref], nil)
		}
		for _, k := range []string{"strictly", "require", "prefer"} {
			if s, ok := t[k].(string); ok {
				return s
			}
		}
	}
	return ""
}
