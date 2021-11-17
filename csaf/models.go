package csaf

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

type TLPLabel string

const (
	TLPLabelUnlabeled = "UNLABELED"
	TLPLabelWhite     = "WHITE"
	TLPLabelGreen     = "GREEN"
	TLPLabelAmber     = "AMBER"
	TLPLabelRed       = "RED"
)

var tlpLabelPattern = alternativesUnmarshal(
	string("UNLABELED"),
	string("WHITE"),
	string("GREEN"),
	string("AMBER"),
	string("RED"))

type JsonURL string

var jsonURLPattern = patternUnmarshal(`\.json$`)

type Feed struct {
	Summary  string    `json:"summary"`
	TLPLabel *TLPLabel `json:"tlp_label"` // required
	URL      *JsonURL  `json:"url"`       // required
}

type ROLIE struct {
	Categories []JsonURL `json:"categories,omitempty"`
	Feeds      []Feed    `json:"feeds"` // required
	Services   []JsonURL `json:"services,omitempty"`
}

type Distribution struct {
	DirectoryURL string  `json:"directory_url,omitempty"`
	Rolie        []ROLIE `json:"rolie"`
}

type TimeStamp time.Time

type Fingerprint string

var fingerprintPattern = patternUnmarshal(`^[0-9a-fA-F]{40,}$`)

type PGPKey struct {
	Fingerprint Fingerprint `json:"fingerprint,omitempty"`
	URL         *string     `json:"url"` // required
}

type CSAFCategory string

const (
	CSAFCategoryCoordinator CSAFCategory = "coordinator"
	CSAFCategoryDiscoverer  CSAFCategory = "discoverer"
	CSAFCategoryOther       CSAFCategory = "other"
	CSAFCategoryTranslator  CSAFCategory = "translator"
	CSAFCategoryUser        CSAFCategory = "user"
	CSAFCategoryVendor      CSAFCategory = "vendor"
)

var csafCategoryPattern = alternativesUnmarshal(
	string(CSAFCategoryCoordinator),
	string(CSAFCategoryDiscoverer),
	string(CSAFCategoryOther),
	string(CSAFCategoryTranslator),
	string(CSAFCategoryUser),
	string(CSAFCategoryVendor))

type CSAFPublisher struct {
	Category         *CSAFCategory `json:"category"`  // required
	Name             *string       `json:"name"`      // required
	Namespace        *string       `json:"namespace"` // required
	ContactDetails   string        `json:"contact_details,omitempty"`
	IssuingAuthority string        `json:"issuing_authority,omitempty"`
}

type MetadataVersion string

const MetadataVersion20 MetadataVersion = "2.0"

var metadataVersionPattern = alternativesUnmarshal(string(MetadataVersion20))

type MetadataRole string

const (
	MetadataRolePublisher       MetadataRole = "csaf_publisher"
	MetadataRoleProvider        MetadataRole = "csaf_provider"
	MetadataRoleTrustedProvider MetadataRole = "csaf_trusted_provider"
)

var metadataRolePattern = alternativesUnmarshal(
	string(MetadataRolePublisher),
	string(MetadataRoleProvider),
	string(MetadataRoleTrustedProvider))

type ProviderURL string

var providerURLPattern = patternUnmarshal(`/provider-metadata\.json$`)

type ProviderMetadata struct {
	CanonicalURL            *ProviderURL     `json:"canonical_url"` // required
	Distributions           []Distribution   `json:"distributions,omitempty"`
	LastUpdated             *TimeStamp       `json:"last_updated"` // required
	ListOnCSAFAggregators   *bool            `json:"list_on_CSAF_aggregators"`
	MetadataVersion         *MetadataVersion `json:"metadata_version"`           // required
	MirrorOnCSAFAggregators *bool            `json:"mirror_on_CSAF_aggregators"` // required
	PGPKeys                 []PGPKey         `json:"pgp_keys,omitempty"`
	Publisher               *CSAFPublisher   `json:"publisher"` // required
	Role                    *MetadataRole    `json:"role"`      // required
}

func patternUnmarshal(pattern string) func([]byte) (string, error) {
	r := regexp.MustCompile(pattern)
	return func(data []byte) (string, error) {
		s := string(data)
		if !r.MatchString(s) {
			return "", fmt.Errorf("%s does not match %v", s, r)
		}
		return s, nil
	}
}

func alternativesUnmarshal(alternatives ...string) func([]byte) (string, error) {
	return func(data []byte) (string, error) {
		s := string(data)
		for _, alt := range alternatives {
			if alt == s {
				return s, nil
			}
		}
		return "", fmt.Errorf("%s not in [%s]", s, strings.Join(alternatives, "|"))
	}
}

func (tl *TLPLabel) UnmarshalText(data []byte) error {
	s, err := tlpLabelPattern(data)
	if err == nil {
		*tl = TLPLabel(s)
	}
	return err
}

func (ju *JsonURL) UnmarshalText(data []byte) error {
	s, err := jsonURLPattern(data)
	if err == nil {
		*ju = JsonURL(s)
	}
	return err
}

func (pu *ProviderURL) UnmarshalText(data []byte) error {
	s, err := providerURLPattern(data)
	if err == nil {
		*pu = ProviderURL(s)
	}
	return err
}

func (cc *CSAFCategory) UnmarshalText(data []byte) error {
	s, err := csafCategoryPattern(data)
	if err == nil {
		*cc = CSAFCategory(s)
	}
	return err
}

func (fp *Fingerprint) UnmarshalText(data []byte) error {
	s, err := fingerprintPattern(data)
	if err == nil {
		*fp = Fingerprint(s)
	}
	return err
}

func (ts *TimeStamp) UnmarshalText(data []byte) error {
	t, err := time.Parse(time.RFC3339, string(data))
	if err != nil {
		return err
	}
	*ts = TimeStamp(t)
	return nil
}

func (ts TimeStamp) MarshalText() ([]byte, error) {
	return []byte(time.Time(ts).Format(time.RFC3339)), nil
}

func (pmd *ProviderMetadata) Defaults() {
	if pmd.Role == nil {
		role := MetadataRoleProvider
		pmd.Role = &role
	}
	if pmd.ListOnCSAFAggregators == nil {
		t := true
		pmd.ListOnCSAFAggregators = &t
	}
	if pmd.MirrorOnCSAFAggregators == nil {
		t := true
		pmd.MirrorOnCSAFAggregators = &t
	}
	if pmd.MetadataVersion == nil {
		mdv := MetadataVersion20
		pmd.MetadataVersion = &mdv
	}
}

func (f *Feed) Validate() error {
	switch {
	case f.TLPLabel == nil:
		return errors.New("feed[].tlp_label is mandatory")
	case f.URL == nil:
		return errors.New("feed[].url is mandatory")
	}
	return nil
}

func (r *ROLIE) Validate() error {
	if len(r.Feeds) < 1 {
		return errors.New("ROLIE needs at least one feed")
	}
	for i := range r.Feeds {
		if err := r.Feeds[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (cp *CSAFPublisher) Validate() error {
	switch {
	case cp == nil:
		return errors.New("publisher is mandatory")
	case cp.Category == nil:
		return errors.New("publisher.category is mandatory")
	case cp.Name == nil:
		return errors.New("publisher.name is mandatory")
	case cp.Namespace == nil:
		return errors.New("publisher.namespace is mandatory")
	}
	return nil
}

func (pk *PGPKey) Validate() error {
	if pk.URL == nil {
		return errors.New("pgp_key[].url is mandatory")
	}
	return nil
}

func (d *Distribution) Validate() error {
	for i := range d.Rolie {
		if err := d.Rolie[i].Validate(); err != nil {
			return nil
		}
	}
	return nil
}

func (pmd *ProviderMetadata) Validate() error {

	switch {
	case pmd.CanonicalURL == nil:
		return errors.New("canonical_url is mandatory")
	case pmd.LastUpdated == nil:
		return errors.New("last_updated is mandatory")
	case pmd.MetadataVersion == nil:
		return errors.New("metadata_version is mandatory")
	}

	if err := pmd.Publisher.Validate(); err != nil {
		return err
	}

	for i := range pmd.PGPKeys {
		if err := pmd.PGPKeys[i].Validate(); err != nil {
			return err
		}
	}

	for i := range pmd.Distributions {
		if err := pmd.Distributions[i].Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (pmd *ProviderMetadata) SetLastUpdated(t time.Time) {
	ts := TimeStamp(t.UTC())
	pmd.LastUpdated = &ts
}

func (pmd *ProviderMetadata) SetPGP(fingerprint, url string) {
	for i := range pmd.PGPKeys {
		if pmd.PGPKeys[i].Fingerprint == Fingerprint(fingerprint) {
			pmd.PGPKeys[i].URL = &url
			return
		}
	}
	pmd.PGPKeys = append(pmd.PGPKeys, PGPKey{
		Fingerprint: Fingerprint(fingerprint),
		URL:         &url,
	})
}

func NewProviderMetadata(canonicalURL string) *ProviderMetadata {
	pmd := new(ProviderMetadata)
	pmd.Defaults()
	pmd.SetLastUpdated(time.Now())
	cu := ProviderURL(canonicalURL)
	pmd.CanonicalURL = &cu
	return pmd
}

func (pm *ProviderMetadata) Save(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(pm)
}

func LoadProviderMetadata(r io.Reader) (*ProviderMetadata, error) {

	var pmd ProviderMetadata
	dec := json.NewDecoder(r)
	if err := dec.Decode(&pmd); err != nil {
		return nil, err
	}

	if err := pmd.Validate(); err != nil {
		return nil, err
	}

	// Set defaults.
	pmd.Defaults()

	return &pmd, nil
}
