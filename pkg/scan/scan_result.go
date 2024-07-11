package scan

import (
	"time"
)

type ScanResult struct {
	SchemaVersion   int              `json:"SchemaVersion"`
	ArtifactName    string           `json:"ArtifactName"`
	ArtifactType    string           `json:"ArtifactType"`
	Metadata        Metadata         `json:"Metadata"`
	DetailedResults []DetailedResult `json:"Results"`
}

type Metadata struct {
	OS          OS          `json:"OS"`
	ImageID     string      `json:"ImageID"`
	DiffIDs     []string    `json:"DiffIDs"`
	RepoTags    []string    `json:"RepoTags"`
	RepoDigests []string    `json:"RepoDigests"`
	ImageConfig ImageConfig `json:"ImageConfig"`
}

type OS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

type ImageConfig struct {
	Architecture string    `json:"architecture"`
	Created      time.Time `json:"created"`
	History      []History `json:"history"`
	Os           string    `json:"os"`
	Rootfs       Rootfs    `json:"rootfs"`
	Config       Config    `json:"config"`
}

type History struct {
	Created    time.Time `json:"created"`
	CreatedBy  string    `json:"created_by"`
	EmptyLayer bool      `json:"empty_layer,omitempty"`
	Comment    string    `json:"comment,omitempty"`
}

type Rootfs struct {
	Type    string   `json:"type"`
	DiffIds []string `json:"diff_ids"`
}

type Config struct {
	Cmd          []string     `json:"Cmd"`
	Entrypoint   []string     `json:"Entrypoint"`
	Env          []string     `json:"Env"`
	Labels       Labels       `json:"Labels"`
	ExposedPorts ExposedPorts `json:"ExposedPorts"`
	ArgsEscaped  bool         `json:"ArgsEscaped"`
	StopSignal   string       `json:"StopSignal"`
}

type Labels struct {
	Maintainer string `json:"maintainer"`
}

type ExposedPorts struct {
	Eight0TCP struct{} `json:"80/tcp"`
}

type DetailedResult struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string     `json:"VulnerabilityID"`
	PkgID            string     `json:"PkgID"`
	PkgName          string     `json:"PkgName"`
	InstalledVersion string     `json:"InstalledVersion"`
	Status           string     `json:"Status"`
	Layer            Layer      `json:"Layer"`
	SeveritySource   string     `json:"SeveritySource"`
	PrimaryURL       string     `json:"PrimaryURL"`
	DataSource       DataSource `json:"DataSource"`
	Title            string     `json:"Title"`
	Description      string     `json:"Description"`
	Severity         string     `json:"Severity"`
	CweIDs           []string   `json:"CweIDs"`
	CVSS             CVSS       `json:"CVSS"`
	References       []string   `json:"References"`
	PublishedDate    time.Time  `json:"PublishedDate"`
	LastModifiedDate time.Time  `json:"LastModifiedDate"`
}

type Layer struct {
	Digest string `json:"Digest"`
	DiffID string `json:"DiffID"`
}

type DataSource struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
	URL  string `json:"URL"`
}

type CVSS struct {
	Nvd Nvd `json:"nvd"`
}

type Nvd struct {
	V2Vector string  `json:"V2Vector"`
	V3Vector string  `json:"V3Vector"`
	V2Score  float64 `json:"V2Score"`
	V3Score  float64 `json:"V3Score"`
}

func (r ScanResult) AnalyzeScanResult(optSeverity ...string) (bool, error) {

	if len(optSeverity) > 0 {
		severity := optSeverity[0]
		return r.ContainsVulnerabilityBySeverity(severity), nil
	}

	return r.ContainsVulnerability(), nil
}

func (r ScanResult) ContainsVulnerabilityBySeverity(severity string) bool {
	for _, result := range r.DetailedResults {
		for _, vuln := range result.Vulnerabilities {
			if vuln.Severity == severity {
				return true
			}
		}
	}
	return false
}

func (r ScanResult) ContainsVulnerability() bool {
	for _, result := range r.DetailedResults {
		if len(result.Vulnerabilities) > 0 {
			return true
		}
	}
	return false
}
