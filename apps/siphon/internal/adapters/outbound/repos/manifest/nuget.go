package manifest

import (
	"encoding/xml"
	"fmt"
	"path"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
)

// .NET packages come from three kinds of file: PackageReference items in
// project files, central versions in Directory.Packages.props, and the older
// packages.config.

type msbuildPackage struct {
	Include              string `xml:"Include,attr"`
	Update               string `xml:"Update,attr"`
	Version              string `xml:"Version,attr"`
	VersionElement       string `xml:"Version"`
	PrivateAssets        string `xml:"PrivateAssets,attr"`
	PrivateAssetsElement string `xml:"PrivateAssets"`
}

func (p msbuildPackage) name() string { return firstNonEmpty(p.Include, p.Update) }

// version is the declared version, or unknown when it is an MSBuild property.
func (p msbuildPackage) version() string {
	v := firstNonEmpty(p.Version, p.VersionElement)
	if strings.Contains(v, "$(") {
		return ""
	}
	return v
}

// buildOnly reports PrivateAssets="all": an analyzer or build tool that does
// not ship with the app.
func (p msbuildPackage) buildOnly() bool {
	return strings.EqualFold(firstNonEmpty(p.PrivateAssets, p.PrivateAssetsElement), "all")
}

type msbuildProject struct {
	ItemGroups []struct {
		References []msbuildPackage `xml:"PackageReference"`
		Versions   []msbuildPackage `xml:"PackageVersion"`
	} `xml:"ItemGroup"`
}

func decodeMSBuild(filePath string, content []byte) (msbuildProject, error) {
	var p msbuildProject
	if err := xml.Unmarshal(content, &p); err != nil {
		return msbuildProject{}, fmt.Errorf("manifest: parse %s: %w", filePath, err)
	}
	return p, nil
}

// MSBuild parses .NET project files (.csproj, .fsproj, .vbproj) and
// Directory.Build.props.
type MSBuild struct{}

// Name identifies the format.
func (MSBuild) Name() string { return ".csproj" }

// Matches reports whether the file is an MSBuild project.
func (MSBuild) Matches(filePath string) bool {
	switch strings.ToLower(path.Ext(filePath)) {
	case ".csproj", ".fsproj", ".vbproj":
		return true
	}
	return path.Base(filePath) == "Directory.Build.props"
}

// Parse maps each PackageReference. Build-only packages are indirect.
func (MSBuild) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	p, err := decodeMSBuild(filePath, content)
	if err != nil {
		return model.RepositorySnapshot{}, err
	}
	var snapshot model.RepositorySnapshot
	for _, group := range p.ItemGroups {
		for _, ref := range group.References {
			if ref.name() == "" {
				continue
			}
			file := filePath
			if ref.buildOnly() {
				file += " (build)"
			}
			snapshot.Dependencies = append(snapshot.Dependencies,
				dependency("nuget", ref.name(), ref.version(), !ref.buildOnly(), file))
		}
	}
	return snapshot, nil
}

// CentralPackages parses Directory.Packages.props, where central package
// management keeps the versions project files leave out.
type CentralPackages struct{}

// Name identifies the format.
func (CentralPackages) Name() string { return "Directory.Packages.props" }

// Matches reports whether the file holds central package versions.
func (CentralPackages) Matches(filePath string) bool {
	return path.Base(filePath) == "Directory.Packages.props"
}

// Parse maps each PackageVersion.
func (CentralPackages) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	p, err := decodeMSBuild(filePath, content)
	if err != nil {
		return model.RepositorySnapshot{}, err
	}
	var snapshot model.RepositorySnapshot
	for _, group := range p.ItemGroups {
		for _, v := range group.Versions {
			if v.name() != "" {
				snapshot.Dependencies = append(snapshot.Dependencies,
					dependency("nuget", v.name(), v.version(), true, filePath))
			}
		}
	}
	return snapshot, nil
}

// PackagesConfig parses the older packages.config.
type PackagesConfig struct{}

// Name identifies the format.
func (PackagesConfig) Name() string { return "packages.config" }

// Matches reports whether the file is a packages.config.
func (PackagesConfig) Matches(filePath string) bool { return path.Base(filePath) == "packages.config" }

// Parse maps each package; developmentDependency ones are indirect.
func (PackagesConfig) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var f struct {
		Packages []struct {
			ID          string `xml:"id,attr"`
			Version     string `xml:"version,attr"`
			Development string `xml:"developmentDependency,attr"`
		} `xml:"package"`
	}
	if err := xml.Unmarshal(content, &f); err != nil {
		return model.RepositorySnapshot{}, fmt.Errorf("manifest: parse %s: %w", filePath, err)
	}
	var snapshot model.RepositorySnapshot
	for _, pkg := range f.Packages {
		if pkg.ID == "" {
			continue
		}
		dev := strings.EqualFold(pkg.Development, "true")
		file := filePath
		if dev {
			file += " (dev)"
		}
		snapshot.Dependencies = append(snapshot.Dependencies, dependency("nuget", pkg.ID, pkg.Version, !dev, file))
	}
	return snapshot, nil
}
