// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package csaf

import (
	"encoding/json"
	"io"
	"os"
)

// Acknowledgement reflects the 'acknowledgement' object in the list of acknowledgements.
// It must at least have one property.
type Acknowledgement struct {
	Names        []*string `json:"names,omitempty"`
	Organization *string   `json:"organization,omitempty"`
	Summary      *string   `json:"summary,omitempty"`
	URLs         []*string `json:"urls,omitempty"`
}

// BranchCategory is the category of a branch.
type BranchCategory string

const (
	// CSAFBranchCategoryArchitecture is the "architecture" category.
	CSAFBranchCategoryArchitecture BranchCategory = "architecture"
	// CSAFBranchCategoryHostName is the "host_name" category.
	CSAFBranchCategoryHostName BranchCategory = "host_name"
	// CSAFBranchCategoryLanguage is the "language" category.
	CSAFBranchCategoryLanguage BranchCategory = "language"
	// CSAFBranchCategoryLegacy is the "legacy" category.
	CSAFBranchCategoryLegacy BranchCategory = "legacy"
	// CSAFBranchCategoryPatchLevel is the "patch_level" category.
	CSAFBranchCategoryPatchLevel BranchCategory = "patch_level"
	// CSAFBranchCategoryProductFamily is the "product_family" category.
	CSAFBranchCategoryProductFamily BranchCategory = "product_family"
	// CSAFBranchCategoryProductName is the "product_name" category.
	CSAFBranchCategoryProductName BranchCategory = "product_name"
	// CSAFBranchCategoryProductVersion is the "product_version" category.
	CSAFBranchCategoryProductVersion BranchCategory = "product_version"
	// CSAFBranchCategoryProductVersionRange is the "product_version_range" category.
	CSAFBranchCategoryProductVersionRange BranchCategory = "product_version_range"
	// CSAFBranchCategoryServicePack is the "service_pack" category.
	CSAFBranchCategoryServicePack BranchCategory = "service_pack"
	// CSAFBranchCategorySpecification is the "specification" category.
	CSAFBranchCategorySpecification BranchCategory = "specification"
	// CSAFBranchCategoryVendor is the "vendor" category.
	CSAFBranchCategoryVendor BranchCategory = "vendor"
)

var csafBranchCategoryPattern = alternativesUnmarshal(
	string(CSAFBranchCategoryArchitecture),
	string(CSAFBranchCategoryHostName),
	string(CSAFBranchCategoryLanguage),
	string(CSAFBranchCategoryLegacy),
	string(CSAFBranchCategoryPatchLevel),
	string(CSAFBranchCategoryProductFamily),
	string(CSAFBranchCategoryProductName),
	string(CSAFBranchCategoryProductVersion),
	string(CSAFBranchCategoryProductVersionRange),
	string(CSAFBranchCategoryServicePack),
	string(CSAFBranchCategorySpecification),
	string(CSAFBranchCategoryVendor))

// ProductID is a reference token for product instances. There is no predefined or
// required format for it as long as it uniquely identifies a product in the context
// of the current document.
type ProductID string

// Products is a list of one or more unique ProductID elements.
type Products []ProductID

// FileHashValue represents the value of a hash.
type FileHashValue string

var FileHashValuePattern = patternUnmarshal(`^[0-9a-fA-F]{32,}$`)

// FileHash is checksum hash.
// Values for 'algorithm' are derived from the currently supported digests OpenSSL. Leading dashes were removed.
type FileHash struct {
	Algorithm string `json:"algorithm"` // required, default: sha256
	Value     string `json:"value"`     // required
}

// Hashes is a list of hashes.
type Hashes struct {
	FileHashes []FileHash `json:"file_hashes"` // required
	FileName   string     `json:"filename"`    // required
}

// CPE represents a Common Platform Enumeration in an advisory.
type CPE string

var CPEPattern = patternUnmarshal("^(cpe:2\\.3:[aho\\*\\-](:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#\\$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|\\}~]))+(\\?*|\\*?))|[\\*\\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\\*\\-]))(:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#\\$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|\\}~]))+(\\?*|\\*?))|[\\*\\-])){4})|([c][pP][eE]:/[AHOaho]?(:[A-Za-z0-9\\._\\-~%]*){0,6})$")

// PURL represents a package URL in an advisory.
type PURL string

var PURLPattern = patternUnmarshal(`^pkg:[A-Za-z\\.\\-\\+][A-Za-z0-9\\.\\-\\+]*/.+`)

// XGenericURI represents an identifier for a product.
type XGenericURI struct {
	Namespace string `json:"namespace"` //  required
	URI       string `json:"uri"`       //  required
}

// ProductIdentificationHelper bundles product identifier information.
// Supported formats for SBOMs are SPDX, CycloneDX, and SWID
type ProductIdentificationHelper struct {
	CPE           *CPE           `json:"cpe,omitempty"`
	Hashes        *Hashes        `json:"hashes,omitempty"`
	ModelNumbers  []*string      `json:"model_numbers,omitempty"` // unique elements
	PURL          *PURL          `json:"purl,omitempty"`
	SBOMURLs      []*string      `json:"sbom_urls,omitempty"`
	SerialNumbers []*string      `json:"serial_numbers,omitempty"` // unique elements
	SKUs          []*string      `json:"skus,omitempty"`
	XGenericURIs  []*XGenericURI `json:"x_generic_uris,omitempty"`
}

// FullProductName is the full name of a product.
type FullProductName struct {
	Name                        string                       `json:"name"`       // required
	ProductID                   ProductID                    `json:"product_id"` // required
	ProductIdentificationHelper *ProductIdentificationHelper `json:"product_identification_helper,omitempty"`
}

// Branch reflects the 'branch' object in the list of branches.
// It may contain either the property Branches OR Product.
// If the category is 'product_version' the name MUST NOT contain
// version ranges of any kind.
// If the category is 'product_version_range' the name MUST contain
// version ranges.
type Branch struct {
	Branches []*Branch        `json:"branches,omitempty"`
	Category BranchCategory   `json:"category"` // required
	Name     string           `json:"name"`     // required
	Product  *FullProductName `json:"product,omitempty"`
}

// NoteCategory is the category of a note.
type NoteCategory string

const (
	// CSAFNoteCategoryDescription is the "description" category.
	CSAFNoteCategoryDescription NoteCategory = "description"
	// CSAFNoteCategoryDetails is the "details" category.
	CSAFNoteCategoryDetails NoteCategory = "details"
	// CSAFNoteCategoryFaq is the "faq" category.
	CSAFNoteCategoryFaq NoteCategory = "faq"
	// CSAFNoteCategoryGeneral is the "general" category.
	CSAFNoteCategoryGeneral NoteCategory = "general"
	// CSAFNoteCategoryLegalDisclaimer is the "legal_disclaimer" category.
	CSAFNoteCategoryLegalDisclaimer NoteCategory = "legal_disclaimer"
	// CSAFNoteCategoryOther is the "other" category.
	CSAFNoteCategoryOther NoteCategory = "other"
	// CSAFNoteCategorySummary is the "summary" category.
	CSAFNoteCategorySummary NoteCategory = "summary"
)

var csafNoteCategoryPattern = alternativesUnmarshal(
	string(CSAFNoteCategoryDescription),
	string(CSAFNoteCategoryDetails),
	string(CSAFNoteCategoryFaq),
	string(CSAFNoteCategoryGeneral),
	string(CSAFNoteCategoryLegalDisclaimer),
	string(CSAFNoteCategoryOther),
	string(CSAFNoteCategorySummary))

// Note reflects the 'Note' object of an advisory.
type Note struct {
	Audience     string        `json:"audience,omitempty"`
	NoteCategory *NoteCategory `json:"category"` // required
	Text         *string       `json:"text"`     // required
	Title        string        `json:"title,omitempty"`
}

// ReferenceCategory is the category of a note.
type ReferenceCategory string

const (
	// CSAFReferenceCategoryExternal is the "external" category.
	CSAFReferenceCategoryExternal ReferenceCategory = "external"
	// CSAFReferenceCategorySelf is the "self" category.
	CSAFReferenceCategorySelf ReferenceCategory = "self"
)

var csafReferenceCategoryPattern = alternativesUnmarshal(
	string(CSAFReferenceCategoryExternal),
	string(CSAFReferenceCategorySelf))

// Reference holding any reference to conferences, papers, advisories, and other
// resources that are related and considered related to either a surrounding part of
// or the entire document and to be of value to the document consumer.
type Reference struct {
	ReferenceCategory *string `json:"category"` // optional, default: external
	Summary           string  `json:"summary"`  // required
	URL               string  `json:"url"`      // required
}

// AggregateSeverity stands for the urgency with which the vulnerabilities of an advisory
// (not a specific one) should be addressed.
type AggregateSeverity struct {
	Namespace *string `json:"namespace,omitempty"`
	Text      string  `json:"text"` // required
}

// DocumentCategory represents a category of a document.
type DocumentCategory string

var DocumentCategoryPattern = patternUnmarshal(`^[^\\s\\-_\\.](.*[^\\s\\-_\\.])?$`)

// CSAFVersion is the version of a document.
type CSAFVersion string

// CSAFVersion is the current version of CSAF.
const CSAFVersion20 CSAFVersion = "2.0"

var CSAFVersionPattern = alternativesUnmarshal(string(CSAFVersion20))

// DocumentTLPLabel is the label of a TLP.
type DocumentTLPLabel string

const (
	// DocumentTLPLabelAmber is the "AMBER" label.
	DocumentTLPLabelAmber DocumentTLPLabel = "AMBER"
	// DocumentTLPLabelGreen is the "GREEN" label.
	DocumentTLPLabelGreen DocumentTLPLabel = "GREEN"
	// DocumentTLPLabelRed is the "RED" label.
	DocumentTLPLabelRed DocumentTLPLabel = "RED"
	// DocumentTLPLabelWhite is the "WHITE" label.
	DocumentTLPLabelWhite DocumentTLPLabel = "WHITE"
)

var csafDocumentTLPLabelPattern = alternativesUnmarshal(
	string(DocumentTLPLabelAmber),
	string(DocumentTLPLabelGreen),
	string(DocumentTLPLabelRed),
	string(DocumentTLPLabelWhite))

// TLP provides details about the TLP classification of the document.
type TLP struct {
	DocumentTLPLabel DocumentTLPLabel `json:"label"` // required
	URL              *string          `json:"url,omitempty"`
}

// DocumentDistribution describes rules for sharing a document.
type DocumentDistribution struct {
	Text *string `json:"text,omitempty"`
	TLP  *TLP    `json:"tlp,omitempty"`
}

// PublisherCategory is the category of a publisher.
type PublisherCategory string

const (
	// CSAFPublisherCategoryCoordinator is the "coordinator" category.
	CSAFPublisherCategoryCoordinator PublisherCategory = "coordinator"
	// CSAFPublisherCategoryDiscoverer is the "discoverer" category.
	CSAFPublisherCategoryDiscoverer PublisherCategory = "discoverer"
	// CSAFPublisherCategoryOther is the "other" category.
	CSAFPublisherCategoryOther PublisherCategory = "other"
	// CSAFPublisherCategoryTranslator is the "translator" category.
	CSAFPublisherCategoryTranslator PublisherCategory = "translator"
	// CSAFPublisherCategoryUser is the "user" category.
	CSAFPublisherCategoryUser PublisherCategory = "user"
	// CSAFPublisherCategoryVendor is the "vendor" category.
	CSAFPublisherCategoryVendor PublisherCategory = "vendor"
)

var csafPublisherCategoryPattern = alternativesUnmarshal(
	string(CSAFPublisherCategoryCoordinator),
	string(CSAFPublisherCategoryDiscoverer),
	string(CSAFPublisherCategoryOther),
	string(CSAFPublisherCategoryTranslator),
	string(CSAFPublisherCategoryUser),
	string(CSAFPublisherCategoryVendor))

// DocumentPublisher provides information about the publishing entity.
type DocumentPublisher struct {
	Category         PublisherCategory `json:"category"` // required
	ContactDetails   *string           `json:"contact_details,omitempty"`
	IssuingAuthority *string           `json:"issuing_authority,omitempty"`
	Name             string            `json:"name"`      // required
	Namespace        string            `json:"namespace"` // required
}

// The version specifies a version string to denote clearly the evolution of the content of the document.
type Version string

var VersionPattern = patternUnmarshal(`^(0|[1-9][0-9]*)$|^((0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)
	(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?)$`)

// Engine contains information about the engine that generated the CSAF document.
type Engine struct {
	Name    string  `json:"name"` // required
	Version *string `json:"version,omitempty"`
}

// Generator holds elements related to the generation of the document.
// These items will reference when the document was actually created,
// including the date it was generated and the entity that generated it.
type Generator struct {
	Date   *string `json:"date,omitempty"`
	Engine Engine  `json:"engine"` // required
}

// TrackingID is a unique identifier for the document.
type TrackingID string

var TrackingIDPattern = patternUnmarshal("^[\\S](.*[\\S])?$")

// Revision contains information about one revision of the document.
type Revision struct {
	Date          string  `json:"date"` // required
	LegacyVersion *string `json:"legacy_version,omitempty"`
	Number        Version `json:"number"`  // required
	Summary       string  `json:"summary"` // required
}

// TrackingStatus is the category of a publisher.
type TrackingStatus string

const (
	// CSAFTrackingStatusDraft is the "draft" category.
	CSAFTrackingStatusDraft TrackingStatus = "draft"
	// CSAFTrackingStatusFinal is the "final" category.
	CSAFTrackingStatusFinal TrackingStatus = "final"
	// CSAFTrackingStatusInterim is the "interim" category.
	CSAFTrackingStatusInterim TrackingStatus = "interim"
)

var csafTrackingStatusPattern = alternativesUnmarshal(
	string(CSAFTrackingStatusDraft),
	string(CSAFTrackingStatusFinal),
	string(CSAFTrackingStatusInterim))

// Tracking holds information that is necessary to track a CSAF document.
type Tracking struct {
	Aliases            []*string      `json:"aliases,omitempty"`    // unique elements
	CurrentReleaseDate string         `json:"current_release_date"` // required
	Generator          *Generator     `json:"generator"`
	ID                 TrackingID     `json:"id"`                   // required
	InitialReleaseDate string         `json:"initial_release_date"` // required
	RevisionHistory    []Revision     `json:"revision_history"`     // required
	Status             TrackingStatus `json:"status"`               // required
	Version            Version        `json:"version"`              // required
}

// Lang is a language identifier, corresponding to IETF BCP 47 / RFC 5646.
type Lang string

var LangPattern = patternUnmarshal("^(([A-Za-z]{2,3}(-[A-Za-z]{3}(-[A-Za-z]{3}){0,2})?|[A-Za-z]{4,8})(-[A-Za-z]{4})?(-([A-Za-z]{2}|[0-9]{3}))?(-([A-Za-z0-9]{5,8}|[0-9][A-Za-z0-9]{3}))*(-[A-WY-Za-wy-z0-9](-[A-Za-z0-9]{2,8})+)*(-[Xx](-[A-Za-z0-9]{1,8})+)?|[Xx](-[A-Za-z0-9]{1,8})+|[Ii]-[Dd][Ee][Ff][Aa][Uu][Ll][Tt]|[Ii]-[Mm][Ii][Nn][Gg][Oo])$")

// Document contains meta-data about an advisory.
type Document struct {
	Acknowledgements  []Acknowledgement     `json:"acknowledgements,omitempty"`
	AggregateSeverity *AggregateSeverity    `json:"aggregate_severity,omitempty"`
	Category          DocumentCategory      `json:"category"`     // required
	CSAFVersion       CSAFVersion           `json:"csaf_version"` // required
	Distribution      *DocumentDistribution `json:"distribution,omitempty"`
	Lang              *Lang                 `json:"lang,omitempty"`
	Notes             []*Note               `json:"notes,omitempty"`
	Publisher         DocumentPublisher     `json:"publisher"` // required
	References        []*Reference          `json:"references,omitempty"`
	SourceLang        *Lang                 `json:"source_lang,omitempty"`
	Title             string                `json:"title"`    // required
	Tracking          Tracking              `json:"tracking"` // required
}

// ProductGroupID is a reference token for product group instances.
type ProductGroupID string

// ProductGroup is a group of products in the document that belong to one group.
type ProductGroup struct {
	GroupID    string   `json:"group_id"`    // required
	ProductIDs Products `json:"product_ids"` // required, two or more unique elements
	Summary    *string  `json:"summary,omitempty"`
}

// ProductGroups is a list of ProductGroupIDs
type ProductGroups struct {
	ProductGroupIDs []ProductGroupID `json:"product_group_ids"` // unique elements
}

// RelationshipCategory is the category of a relationship.
type RelationshipCategory string

const (
	// CSAFRelationshipCategoryDefaultComponentOf is the "default_component_of" category.
	CSAFRelationshipCategoryDefaultComponentOf RelationshipCategory = "default_component_of"
	// CSAFRelationshipCategoryExternalComponentOf is the "external_component_of" category.
	CSAFRelationshipCategoryExternalComponentOf RelationshipCategory = "external_component_of"
	// CSAFRelationshipCategoryInstalledOn is the "installed_on" category.
	CSAFRelationshipCategoryInstalledOn RelationshipCategory = "installed_on"
	// CSAFRelationshipCategoryInstalledWith is the "installed_with" category.
	CSAFRelationshipCategoryInstalledWith RelationshipCategory = "installed_with"
	// CSAFRelationshipCategoryOptionalComponentOf is the "optional_component_of" category.
	CSAFRelationshipCategoryOptionalComponentOf RelationshipCategory = "optional_component_of"
)

var csafRelationshipCategoryPattern = alternativesUnmarshal(
	string(CSAFRelationshipCategoryDefaultComponentOf),
	string(CSAFRelationshipCategoryExternalComponentOf),
	string(CSAFRelationshipCategoryInstalledOn),
	string(CSAFRelationshipCategoryInstalledWith),
	string(CSAFRelationshipCategoryOptionalComponentOf))

// Relationship establishes a link between two existing FullProductName elements.
type Relationship struct {
	Category                  RelationshipCategory `json:"category"`                     // required
	FullProductName           FullProductName      `json:"full_product_name"`            // required
	ProductReference          ProductID            `json:"product_reference"`            // required
	RelatesToProductReference ProductID            `json:"relates_to_product_reference"` // required

}

// ProductTree contains product names that can be referenced elsewhere in the document.
type ProductTree struct {
	Branches         []*Branch          `json:"branches,omitempty"`
	FullProductNames []*FullProductName `json:"full_product_name,omitempty"`
	ProductGroups    *ProductGroups     `json:"product_groups,omitempty"`
	RelationShips    []*Relationship    `json:"relationships,omitempty"`
}

// CVE holds the MITRE standard Common Vulnerabilities and Exposures (CVE) tracking number for a vulnerability.
type CVE string

var CVEPattern = patternUnmarshal("^CVE-[0-9]{4}-[0-9]{4,}$")

// WeaknessID is the identifier of a weakness.
type WeaknessID string

var WeaknessIDPattern = patternUnmarshal("^CWE-[1-9]\\d{0,5}$")

// CWE holds the MITRE standard Common Weakness Enumeration (CWE) for the weakness associated.
type CWE struct {
	ID   WeaknessID `json:"id"`   // required
	Name string     `json:"name"` // required
}

// FlagLabel is the label of a flag for a vulnerability.
type FlagLabel string

const (
	// CSAFFlagLabelComponentNotPresent is the "component_not_present" label.
	CSAFFlagLabelComponentNotPresent FlagLabel = "component_not_present"
	// CSAFFlagLabelInlineMitigationsAlreadyExist is the "inline_mitigations_already_exist" label.
	CSAFFlagLabelInlineMitigationsAlreadyExist FlagLabel = "inline_mitigations_already_exist"
	// CSAFFlagLabelVulnerableCodeCannotBeControlledByAdversary is the "vulnerable_code_cannot_be_controlled_by_adversary" label.
	CSAFFlagLabelVulnerableCodeCannotBeControlledByAdversary FlagLabel = "vulnerable_code_cannot_be_controlled_by_adversary"
	// CSAFFlagLabelVulnerableCodeNotInExecutePath is the "vulnerable_code_not_in_execute_path" label.
	CSAFFlagLabelVulnerableCodeNotInExecutePath FlagLabel = "vulnerable_code_not_in_execute_path"
	// CSAFFlagLabelVulnerableCodeNotPresent is the "vulnerable_code_not_present" label.
	CSAFFlagLabelVulnerableCodeNotPresent FlagLabel = "vulnerable_code_not_present"
)

var csafFlagLabelPattern = alternativesUnmarshal(
	string(CSAFFlagLabelComponentNotPresent),
	string(CSAFFlagLabelInlineMitigationsAlreadyExist),
	string(CSAFFlagLabelVulnerableCodeCannotBeControlledByAdversary),
	string(CSAFFlagLabelVulnerableCodeNotInExecutePath),
	string(CSAFFlagLabelVulnerableCodeNotPresent))

// Flag contains product specific information in regard to this vulnerability as a single
// machine readable flag. For example, this could be a machine readable justification
// code why a product is not affected.
type Flag struct {
	Date       *string        `json:"date,omitempty"`
	GroupIds   *ProductGroups `json:"group_ids,omitempty"`
	Label      FlagLabel      `json:"label"` // required
	ProductIds *Products      `json:"product_ids,omitempty"`
}

// VulnerabilityID is the identifier of a vulnerability.
type VulnerabilityID struct {
	SystemName string `json:"system_name"` // required
	Text       string `json:"text"`        // required
}

// InvolvementParty is the party of an involvement.
type InvolvementParty string

const (
	// CSAFInvolvementPartyCoordinator is the "coordinator" party.
	CSAFInvolvementPartyCoordinator InvolvementParty = "coordinator"
	// CSAFInvolvementPartyDiscoverer is the "discoverer" party.
	CSAFInvolvementPartyDiscoverer InvolvementParty = "discoverer"
	// CSAFInvolvementPartyOther is the "other" party.
	CSAFInvolvementPartyOther InvolvementParty = "other"
	// CSAFInvolvementPartyUser is the "user" party.
	CSAFInvolvementPartyUser InvolvementParty = "user"
	// CSAFInvolvementPartyVendor is the "vendor" party.
	CSAFInvolvementPartyVendor InvolvementParty = "vendor"
)

var csafInvolvementPartyPattern = alternativesUnmarshal(
	string(CSAFInvolvementPartyCoordinator),
	string(CSAFInvolvementPartyDiscoverer),
	string(CSAFInvolvementPartyOther),
	string(CSAFInvolvementPartyUser),
	string(CSAFInvolvementPartyVendor))

// InvolvementStatus is the status of an involvement.
type InvolvementStatus string

const (
	// CSAFInvolvementStatusCompleted is the "completed" status.
	CSAFInvolvementStatusCompleted InvolvementStatus = "completed"
	// CSAFInvolvementStatusContactAttempted is the "contact_attempted" status.
	CSAFInvolvementStatusContactAttempted InvolvementStatus = "contact_attempted"
	// CSAFInvolvementStatusDisputed is the "disputed" status.
	CSAFInvolvementStatusDisputed InvolvementStatus = "disputed"
	// CSAFInvolvementStatusInProgress is the "in_progress" status.
	CSAFInvolvementStatusInProgress InvolvementStatus = "in_progress"
	// CSAFInvolvementStatusNotContacted is the "not_contacted" status.
	CSAFInvolvementStatusNotContacted InvolvementStatus = "not_contacted"
	// CSAFInvolvementStatusOpen is the "open" status.
	CSAFInvolvementStatusOpen InvolvementStatus = "open"
)

var csafInvolvementStatusPattern = alternativesUnmarshal(
	string(CSAFInvolvementStatusCompleted),
	string(CSAFInvolvementStatusContactAttempted),
	string(CSAFInvolvementStatusDisputed),
	string(CSAFInvolvementStatusInProgress),
	string(CSAFInvolvementStatusNotContacted),
	string(CSAFInvolvementStatusOpen))

// Involvement is a container that allows the document producers to comment on the level of involvement
// (or engagement) of themselves (or third parties) in the vulnerability identification, scoping, and
// remediation process. It can also be used to convey the disclosure timeline.
// The ordered tuple of the values of party and date (if present) SHALL be unique within the involvements
// of a vulnerability.
type Involvement struct {
	Date    *string           `json:"date,omitempty"`
	Party   InvolvementParty  `json:"party"`  // required
	Status  InvolvementStatus `json:"status"` // required
	Summary *string           `json:"summary,omitempty"`
}

// ProductStatus contains different lists of ProductIDs which provide details on
// the status of the referenced product related to the current vulnerability.
type ProductStatus struct {
	FirstAffected      *Products `json:"first_affected,omitempty"`
	FirstFixed         *Products `json:"first_fixed,omitempty"`
	Fixed              *Products `json:"fixed,omitempty"`
	KnownAffected      *Products `json:"known_affected,omitempty"`
	KnownNotAffected   *Products `json:"known_not_affected,omitempty"`
	LastAffected       *Products `json:"last_affected,omitempty"`
	Recommended        *Products `json:"recommended,omitempty"`
	UnderInvestigation *Products `json:"under_investigation,omitempty"`
}

// RemediationCategory is the category of a remediation.
type RemediationCategory string

const (
	// CSAFRemediationCategoryMitigation is the "mitigation" category.
	CSAFRemediationCategoryMitigation RemediationCategory = "mitigation"
	// CSAFRemediationCategoryNoFixPlanned is the "no_fix_planned" category.
	CSAFRemediationCategoryNoFixPlanned RemediationCategory = "no_fix_planned"
	// CSAFRemediationCategoryNoneAvailable is the "none_available" category.
	CSAFRemediationCategoryNoneAvailable RemediationCategory = "none_available"
	// CSAFRemediationCategoryVendorFix is the "vendor_fix" category.
	CSAFRemediationCategoryVendorFix RemediationCategory = "vendor_fix"
	// CSAFRemediationCategoryWorkaround is the "workaround" category.
	CSAFRemediationCategoryWorkaround RemediationCategory = "workaround"
)

var csafRemediationCategoryPattern = alternativesUnmarshal(
	string(CSAFRemediationCategoryMitigation),
	string(CSAFRemediationCategoryNoFixPlanned),
	string(CSAFRemediationCategoryNoneAvailable),
	string(CSAFRemediationCategoryVendorFix),
	string(CSAFRemediationCategoryWorkaround))

// RestartRequiredCategory is the category of RestartRequired.
type RestartRequiredCategory string

const (
	// CSAFRestartRequiredCategoryConnected is the "connected" category.
	CSAFRestartRequiredCategoryConnected RestartRequiredCategory = "connected"
	// CSAFRestartRequiredCategoryDependencies is the "dependencies" category.
	CSAFRestartRequiredCategoryDependencies RestartRequiredCategory = "dependencies"
	// CSAFRestartRequiredCategoryMachine is the "machine" category.
	CSAFRestartRequiredCategoryMachine RestartRequiredCategory = "machine"
	// CSAFRestartRequiredCategoryNone is the "none" category.
	CSAFRestartRequiredCategoryNone RestartRequiredCategory = "none"
	// CSAFRestartRequiredCategoryParent is the "parent" category.
	CSAFRestartRequiredCategoryParent RestartRequiredCategory = "parent"
	// CSAFRestartRequiredCategoryService is the "service" category.
	CSAFRestartRequiredCategoryService RestartRequiredCategory = "service"
	// CSAFRestartRequiredCategorySystem is the "system" category.
	CSAFRestartRequiredCategorySystem RestartRequiredCategory = "system"
	// CSAFRestartRequiredCategoryVulnerableComponent is the "vulnerable_component" category.
	CSAFRestartRequiredCategoryVulnerableComponent RestartRequiredCategory = "vulnerable_component"
	// CSAFRestartRequiredCategoryZone is the "zone" category.
	CSAFRestartRequiredCategoryZone RestartRequiredCategory = "zone"
)

var csafRestartRequiredCategoryPattern = alternativesUnmarshal(
	string(CSAFRestartRequiredCategoryConnected),
	string(CSAFRestartRequiredCategoryDependencies),
	string(CSAFRestartRequiredCategoryMachine),
	string(CSAFRestartRequiredCategoryNone),
	string(CSAFRestartRequiredCategoryParent),
	string(CSAFRestartRequiredCategoryService),
	string(CSAFRestartRequiredCategorySystem),
	string(CSAFRestartRequiredCategoryVulnerableComponent),
	string(CSAFRestartRequiredCategoryZone))

// RestartRequired provides information on category of restart is required by this remediation to become
// effective.
type RestartRequired struct {
	Category RestartRequiredCategory `json:"category"` // required
	Details  *string                 `json:"details,omitempty"`
}

// Remediation specifies details on how to handle (and presumably, fix) a vulnerability.
type Remediation struct {
	Category        *RemediationCategory `json:"category"` // required
	Date            *string              `json:"date,omitempty"`
	Details         *string              `json:"details"` // required
	Entitlements    []*string            `json:"entitlements,omitempty"`
	GroupIds        *ProductGroups       `json:"group_ids,omitempty"`
	ProductIds      *Products            `json:"product_ids,omitempty"`
	RestartRequired *RestartRequired     `json:"restart_required,omitempty"`
	URL             *string              `json:"url,omitempty"`
}

// CVSSv3Version is the version of a CVSSv3 item.
type CVSSv3Version string

// CVSSv3Version30 is version 3.0 of a CVSSv3 item.
const CVSSv3Version30 CVSSv3Version = "3.0"

// CVSSv3Version31 is version 3.1 of a CVSSv3 item.
const CVSSv3Version31 CVSSv3Version = "3.1"

// CVSSv3VectorString is the VectorString of a CVSSv3 item with version 3.x.
type CVSSv3VectorString string

var CVSSv3VectorStringPattern = patternUnmarshal(`^CVSS:3[.][01]/((AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])/)*(AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$`)

var CVSSv3VersionPattern = alternativesUnmarshal(
	string(CVSSv3Version30),
	string(CVSSv3Version31))

// CVSSv2 holding a CVSS v2.0 value
type CVSSv2 struct {
	Version                    string                           `json:"version"`      // required
	VectorString               string                           `json:"vectorString"` // required
	AccessVector               *CVSS20AccessVector              `json:"accessVector"`
	AccessComplexity           *CVSS20AccessComplexity          `json:"accessComplexity"`
	Authentication             *CVSS20Authentication            `json:"authentication"`
	ConfidentialityImpact      *string                          `json:"confidentialityImpact"`
	IntegrityImpact            *string                          `json:"integrityImpact"`
	AvailabilityImpact         *string                          `json:"availabilityImpact"`
	BaseScore                  float64                          `json:"baseScore"` // required
	Exploitability             *CVSS20Exploitability            `json:"exploitability"`
	RemediationLevel           *CVSS20RemediationLevel          `json:"remediationLevel"`
	ReportConfidence           *string                          `json:"reportConfidence"`
	TemporalScore              *string                          `json:"temporalScore"`
	CollateralDamagePotential  *CVSS20CollateralDamagePotential `json:"collateralDamagePotential"`
	TargetDistribution         *CVSS20TargetDistribution        `json:"targetDistribution"`
	ConfidentialityRequirement *string                          `json:"confidentialityRequirement"`
	IntegrityRequirement       *string                          `json:"integrityRequirement"`
	AvailabilityRequirement    *string                          `json:"availabilityRequirement"`
	EnvironmentalScore         *string                          `json:"environmentalScore"`
}

// CVSSv3 holding a CVSS v3.x value
type CVSSv3 struct {
	Version                       string                          `json:"version"`      // required
	VectorString                  string                          `json:"vectorString"` // required
	AttackVector                  *string                         `json:"attackVector"`
	AttackComplexity              *CVSS30AttackComplexity         `json:"attackComplexity"`
	PrivilegesRequired            *CVSS30PrivilegesRequired       `json:"privilegesRequired"`
	UserInteraction               *CVSS30UserInteraction          `json:"userInteraction"`
	Scope                         *CVSS30Scope                    `json:"scope"`
	ConfidentialityImpact         *string                         `json:"confidentialityImpact"`
	IntegrityImpact               string                          `json:"integrityImpact"`
	AvailabilityImpact            *string                         `json:"availabilityImpact"`
	BaseScore                     float64                         `json:"baseScore"`    // required
	BaseSeverity                  string                          `json:"baseSeverity"` // required
	ExploitCodeMaturity           *CVSS30ExploitCodeMaturity      `json:"exploitCodeMaturity"`
	RemediationLevel              *CVSS30RemediationLevel         `json:"remediationLevel"`
	ReportConfidence              *string                         `json:"reportConfidence"`
	TemporalScore                 *string                         `json:"temporalScore"`
	TemporalSeverity              *string                         `json:"temporalSeverity"`
	ConfidentialityRequirement    *string                         `json:"confidentialityRequirement"`
	IntegrityRequirement          *string                         `json:"integrityRequirement"`
	AvailabilityRequirement       *string                         `json:"availabilityRequirement"`
	ModifiedAttackVector          *CVSS30ModifiedAttackVector     `json:"modifiedAttackVector"`
	ModifiedAttackComplexity      *CVSS30ModifiedAttackComplexity `json:"modifiedAttackComplexity"`
	ModifiedPrivilegesRequired    *string                         `json:"modifiedPrivilegesRequired"`
	ModifiedUserInteraction       *string                         `json:"modifiedUserInteraction"`
	ModifiedScope                 *string                         `json:"modifiedScope"`
	ModifiedConfidentialityImpact *string                         `json:"modifiedConfidentialityImpact"`
	ModifiedIntegrityImpact       *string                         `json:"modifiedIntegrityImpact"`
	ModifiedAvailabilityImpact    *string                         `json:"modifiedAvailabilityImpact"`
	EenvironmentalScore           *string                         `json:"environmentalScore"`
	EnvironmentalSeverity         *string                         `json:"environmentalSeverity"`
}

// Score specifies information about (at least one) score of the vulnerability and for which
// products the given value applies. A Score item has at least 2 properties.
type Score struct {
	CVSSv2   *CVSSv2   `json:"cvss_v2,omitempty"`
	CVSSv3   *CVSSv3   `json:"cvss_v3,omitempty"`
	Products *Products `json:"products"` // required
}

// ThreatCategory is the category of a threat.
type ThreatCategory string

const (
	// CSAFThreatCategoryExploitStatus is the "exploit_status" category.
	CSAFThreatCategoryExploitStatus ThreatCategory = "exploit_status"
	// CSAFThreatCategoryImpact is the "impact" category.
	CSAFThreatCategoryImpact ThreatCategory = "impact"
	// CSAFThreatCategoryTargetSet is the "target_set" category.
	CSAFThreatCategoryTargetSet ThreatCategory = "target_set"
)

var csafThreatCategoryPattern = alternativesUnmarshal(
	string(CSAFThreatCategoryExploitStatus),
	string(CSAFThreatCategoryImpact),
	string(CSAFThreatCategoryTargetSet))

// Threat contains information about a vulnerability that can change with time.
type Threat struct {
	Category   ThreatCategory `json:"category"` // required
	Date       *string        `json:"date,omitempty"`
	Details    string         `json:"details"` // required
	GroupIds   *ProductGroups `json:"group_ids,omitempty"`
	ProductIds *Products      `json:"product_ids,omitempty"`
}

// Vulnerability contains all fields that are related to a single vulnerability in the document.
type Vulnerability struct {
	Acknowledgements []*Acknowledgement `json:"acknowledgements,omitempty"`
	CVE              *CVE               `json:"cve,omitempty"`
	CWE              *CWE               `json:"cwe,omitempty"`
	DiscoveryDate    *string            `json:"discovery_date,omitempty"`
	Flags            []*Flag            `json:"flags,omitempty"`
	Ids              []*VulnerabilityID `json:"ids,omitempty"` // unique ID elements
	Involvements     []*Involvement     `json:"involvements,omitempty"`
	Notes            []*Note            `json:"notes,omitempty"`
	ProductStatus    *ProductStatus     `json:"product_status,omitempty"`
	References       []*Reference       `json:"references,omitempty"`
	ReleaseDate      *string            `json:"release_date,omitempty"`
	Remediations     []*Remediation     `json:"remediations,omitempty"`
	Scores           []*Score           `json:"scores,omitempty"`
	Threats          []*Threat          `json:"threats,omitempty"`
	Title            *string            `json:"title,omitempty"`
}

// Advisory represents a CSAF advisory.
type Advisory struct {
	Document        Document         `json:"document"` // required
	ProductTree     *ProductTree     `json:"product_tree,omitempty"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities,omitempty"`
}

// Validate checks if the advisory is valid.
// Returns an error if the validation fails otherwise nil.
func (adv *Advisory) Validate() error {
	// TODO
	return nil
}

// LoadAdvisory loads an advisory from a file.
func LoadAdvisory(fname string) (*Advisory, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var advisory Advisory
	if err := json.NewDecoder(f).Decode(&advisory); err != nil {
		return nil, err
	}
	return &advisory, nil
}

// SaveAdvisory writes the JSON encoding of the given advisory to a
// file with the given name.
// It returns nil, otherwise an error.
func SaveAdvisory(adv *Advisory, fname string) error {
	var w io.WriteCloser
	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	w = f

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	err = enc.Encode(adv)
	if e := w.Close(); err != nil {
		err = e
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (bc *BranchCategory) UnmarshalText(data []byte) error {
	s, err := csafBranchCategoryPattern(data)
	if err == nil {
		*bc = BranchCategory(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (nc *NoteCategory) UnmarshalText(data []byte) error {
	s, err := csafNoteCategoryPattern(data)
	if err == nil {
		*nc = NoteCategory(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (rc *ReferenceCategory) UnmarshalText(data []byte) error {
	s, err := csafReferenceCategoryPattern(data)
	if err == nil {
		*rc = ReferenceCategory(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (dtl *DocumentTLPLabel) UnmarshalText(data []byte) error {
	s, err := csafDocumentTLPLabelPattern(data)
	if err == nil {
		*dtl = DocumentTLPLabel(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (pc *PublisherCategory) UnmarshalText(data []byte) error {
	s, err := csafPublisherCategoryPattern(data)
	if err == nil {
		*pc = PublisherCategory(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (ts *TrackingStatus) UnmarshalText(data []byte) error {
	s, err := csafTrackingStatusPattern(data)
	if err == nil {
		*ts = TrackingStatus(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (rc *RelationshipCategory) UnmarshalText(data []byte) error {
	s, err := csafRelationshipCategoryPattern(data)
	if err == nil {
		*rc = RelationshipCategory(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (fl *FlagLabel) UnmarshalText(data []byte) error {
	s, err := csafFlagLabelPattern(data)
	if err == nil {
		*fl = FlagLabel(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (ip *InvolvementParty) UnmarshalText(data []byte) error {
	s, err := csafInvolvementPartyPattern(data)
	if err == nil {
		*ip = InvolvementParty(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (is *InvolvementStatus) UnmarshalText(data []byte) error {
	s, err := csafInvolvementStatusPattern(data)
	if err == nil {
		*is = InvolvementStatus(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (rc *RemediationCategory) UnmarshalText(data []byte) error {
	s, err := csafRemediationCategoryPattern(data)
	if err == nil {
		*rc = RemediationCategory(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (rrc *RestartRequiredCategory) UnmarshalText(data []byte) error {
	s, err := csafRestartRequiredCategoryPattern(data)
	if err == nil {
		*rrc = RestartRequiredCategory(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (tc *ThreatCategory) UnmarshalText(data []byte) error {
	s, err := csafThreatCategoryPattern(data)
	if err == nil {
		*tc = ThreatCategory(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (cpe *CPE) UnmarshalText(data []byte) error {
	s, err := CPEPattern(data)
	if err == nil {
		*cpe = CPE(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (fhv *FileHashValue) UnmarshalText(data []byte) error {
	s, err := FileHashValuePattern(data)
	if err == nil {
		*fhv = FileHashValue(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (p *PURL) UnmarshalText(data []byte) error {
	s, err := PURLPattern(data)
	if err == nil {
		*p = PURL(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (l *Lang) UnmarshalText(data []byte) error {
	s, err := LangPattern(data)
	if err == nil {
		*l = Lang(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (v *Version) UnmarshalText(data []byte) error {
	s, err := VersionPattern(data)
	if err == nil {
		*v = Version(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (dc *DocumentCategory) UnmarshalText(data []byte) error {
	s, err := DocumentCategoryPattern(data)
	if err == nil {
		*dc = DocumentCategory(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (cv *CSAFVersion) UnmarshalText(data []byte) error {
	s, err := CSAFVersionPattern(data)
	if err == nil {
		*cv = CSAFVersion(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (ti *TrackingID) UnmarshalText(data []byte) error {
	s, err := TrackingIDPattern(data)
	if err == nil {
		*ti = TrackingID(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (cve *CVE) UnmarshalText(data []byte) error {
	s, err := CVEPattern(data)
	if err == nil {
		*cve = CVE(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (wi *WeaknessID) UnmarshalText(data []byte) error {
	s, err := WeaknessIDPattern(data)
	if err == nil {
		*wi = WeaknessID(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (cv *CVSSv3Version) UnmarshalText(data []byte) error {
	s, err := CVSSv3VersionPattern(data)
	if err == nil {
		*cv = CVSSv3Version(s)
	}
	return err
}

// UnmarshalText implements the encoding.TextUnmarshaller interface.
func (cvs *CVSSv3VectorString) UnmarshalText(data []byte) error {
	s, err := CVSSv3VectorStringPattern(data)
	if err == nil {
		*cvs = CVSSv3VectorString(s)
	}
	return err
}
