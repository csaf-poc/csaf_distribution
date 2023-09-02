// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>
//
// THIS FILE IS MACHINE GENERATED. EDIT WITH CARE!

package csaf

// CVSS30AttackComplexity represents the attackComplexityType in CVSS30.
type CVSS30AttackComplexity string

const (
	// CVSS30AttackComplexityHigh is a constant for "HIGH".
	CVSS30AttackComplexityHigh CVSS30AttackComplexity = "HIGH"
	// CVSS30AttackComplexityLow is a constant for "LOW".
	CVSS30AttackComplexityLow CVSS30AttackComplexity = "LOW"
)

var cvss30AttackComplexityPattern = alternativesUnmarshal(
	string(CVSS30AttackComplexityHigh),
	string(CVSS30AttackComplexityLow),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS30AttackComplexity) UnmarshalText(data []byte) error {
	s, err := cvss30AttackComplexityPattern(data)
	if err == nil {
		*e = CVSS30AttackComplexity(s)
	}
	return err
}

// CVSS30AttackVector represents the attackVectorType in CVSS30.
type CVSS30AttackVector string

const (
	// CVSS30AttackVectorNetwork is a constant for "NETWORK".
	CVSS30AttackVectorNetwork CVSS30AttackVector = "NETWORK"
	// CVSS30AttackVectorAdjacentNetwork is a constant for "ADJACENT_NETWORK".
	CVSS30AttackVectorAdjacentNetwork CVSS30AttackVector = "ADJACENT_NETWORK"
	// CVSS30AttackVectorLocal is a constant for "LOCAL".
	CVSS30AttackVectorLocal CVSS30AttackVector = "LOCAL"
	// CVSS30AttackVectorPhysical is a constant for "PHYSICAL".
	CVSS30AttackVectorPhysical CVSS30AttackVector = "PHYSICAL"
)

var cvss30AttackVectorPattern = alternativesUnmarshal(
	string(CVSS30AttackVectorNetwork),
	string(CVSS30AttackVectorAdjacentNetwork),
	string(CVSS30AttackVectorLocal),
	string(CVSS30AttackVectorPhysical),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS30AttackVector) UnmarshalText(data []byte) error {
	s, err := cvss30AttackVectorPattern(data)
	if err == nil {
		*e = CVSS30AttackVector(s)
	}
	return err
}

// CVSS30CiaRequirement represents the ciaRequirementType in CVSS30.
type CVSS30CiaRequirement string

const (
	// CVSS30CiaRequirementLow is a constant for "LOW".
	CVSS30CiaRequirementLow CVSS30CiaRequirement = "LOW"
	// CVSS30CiaRequirementMedium is a constant for "MEDIUM".
	CVSS30CiaRequirementMedium CVSS30CiaRequirement = "MEDIUM"
	// CVSS30CiaRequirementHigh is a constant for "HIGH".
	CVSS30CiaRequirementHigh CVSS30CiaRequirement = "HIGH"
	// CVSS30CiaRequirementNotDefined is a constant for "NOT_DEFINED".
	CVSS30CiaRequirementNotDefined CVSS30CiaRequirement = "NOT_DEFINED"
)

var cvss30CiaRequirementPattern = alternativesUnmarshal(
	string(CVSS30CiaRequirementLow),
	string(CVSS30CiaRequirementMedium),
	string(CVSS30CiaRequirementHigh),
	string(CVSS30CiaRequirementNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS30CiaRequirement) UnmarshalText(data []byte) error {
	s, err := cvss30CiaRequirementPattern(data)
	if err == nil {
		*e = CVSS30CiaRequirement(s)
	}
	return err
}

// CVSS30Cia represents the ciaType in CVSS30.
type CVSS30Cia string

const (
	// CVSS30CiaNone is a constant for "NONE".
	CVSS30CiaNone CVSS30Cia = "NONE"
	// CVSS30CiaLow is a constant for "LOW".
	CVSS30CiaLow CVSS30Cia = "LOW"
	// CVSS30CiaHigh is a constant for "HIGH".
	CVSS30CiaHigh CVSS30Cia = "HIGH"
)

var cvss30CiaPattern = alternativesUnmarshal(
	string(CVSS30CiaNone),
	string(CVSS30CiaLow),
	string(CVSS30CiaHigh),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS30Cia) UnmarshalText(data []byte) error {
	s, err := cvss30CiaPattern(data)
	if err == nil {
		*e = CVSS30Cia(s)
	}
	return err
}

// CVSS30Confidence represents the confidenceType in CVSS30.
type CVSS30Confidence string

const (
	// CVSS30ConfidenceUnknown is a constant for "UNKNOWN".
	CVSS30ConfidenceUnknown CVSS30Confidence = "UNKNOWN"
	// CVSS30ConfidenceReasonable is a constant for "REASONABLE".
	CVSS30ConfidenceReasonable CVSS30Confidence = "REASONABLE"
	// CVSS30ConfidenceConfirmed is a constant for "CONFIRMED".
	CVSS30ConfidenceConfirmed CVSS30Confidence = "CONFIRMED"
	// CVSS30ConfidenceNotDefined is a constant for "NOT_DEFINED".
	CVSS30ConfidenceNotDefined CVSS30Confidence = "NOT_DEFINED"
)

var cvss30ConfidencePattern = alternativesUnmarshal(
	string(CVSS30ConfidenceUnknown),
	string(CVSS30ConfidenceReasonable),
	string(CVSS30ConfidenceConfirmed),
	string(CVSS30ConfidenceNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS30Confidence) UnmarshalText(data []byte) error {
	s, err := cvss30ConfidencePattern(data)
	if err == nil {
		*e = CVSS30Confidence(s)
	}
	return err
}

// CVSS30ExploitCodeMaturity represents the exploitCodeMaturityType in CVSS30.
type CVSS30ExploitCodeMaturity string

const (
	// CVSS30ExploitCodeMaturityUnproven is a constant for "UNPROVEN".
	CVSS30ExploitCodeMaturityUnproven CVSS30ExploitCodeMaturity = "UNPROVEN"
	// CVSS30ExploitCodeMaturityProofOfConcept is a constant for "PROOF_OF_CONCEPT".
	CVSS30ExploitCodeMaturityProofOfConcept CVSS30ExploitCodeMaturity = "PROOF_OF_CONCEPT"
	// CVSS30ExploitCodeMaturityFunctional is a constant for "FUNCTIONAL".
	CVSS30ExploitCodeMaturityFunctional CVSS30ExploitCodeMaturity = "FUNCTIONAL"
	// CVSS30ExploitCodeMaturityHigh is a constant for "HIGH".
	CVSS30ExploitCodeMaturityHigh CVSS30ExploitCodeMaturity = "HIGH"
	// CVSS30ExploitCodeMaturityNotDefined is a constant for "NOT_DEFINED".
	CVSS30ExploitCodeMaturityNotDefined CVSS30ExploitCodeMaturity = "NOT_DEFINED"
)

var cvss30ExploitCodeMaturityPattern = alternativesUnmarshal(
	string(CVSS30ExploitCodeMaturityUnproven),
	string(CVSS30ExploitCodeMaturityProofOfConcept),
	string(CVSS30ExploitCodeMaturityFunctional),
	string(CVSS30ExploitCodeMaturityHigh),
	string(CVSS30ExploitCodeMaturityNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS30ExploitCodeMaturity) UnmarshalText(data []byte) error {
	s, err := cvss30ExploitCodeMaturityPattern(data)
	if err == nil {
		*e = CVSS30ExploitCodeMaturity(s)
	}
	return err
}

// CVSS30ModifiedAttackComplexity represents the modifiedAttackComplexityType in CVSS30.
type CVSS30ModifiedAttackComplexity string

const (
	// CVSS30ModifiedAttackComplexityHigh is a constant for "HIGH".
	CVSS30ModifiedAttackComplexityHigh CVSS30ModifiedAttackComplexity = "HIGH"
	// CVSS30ModifiedAttackComplexityLow is a constant for "LOW".
	CVSS30ModifiedAttackComplexityLow CVSS30ModifiedAttackComplexity = "LOW"
	// CVSS30ModifiedAttackComplexityNotDefined is a constant for "NOT_DEFINED".
	CVSS30ModifiedAttackComplexityNotDefined CVSS30ModifiedAttackComplexity = "NOT_DEFINED"
)

var cvss30ModifiedAttackComplexityPattern = alternativesUnmarshal(
	string(CVSS30ModifiedAttackComplexityHigh),
	string(CVSS30ModifiedAttackComplexityLow),
	string(CVSS30ModifiedAttackComplexityNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS30ModifiedAttackComplexity) UnmarshalText(data []byte) error {
	s, err := cvss30ModifiedAttackComplexityPattern(data)
	if err == nil {
		*e = CVSS30ModifiedAttackComplexity(s)
	}
	return err
}

// CVSS30ModifiedAttackVector represents the modifiedAttackVectorType in CVSS30.
type CVSS30ModifiedAttackVector string

const (
	// CVSS30ModifiedAttackVectorNetwork is a constant for "NETWORK".
	CVSS30ModifiedAttackVectorNetwork CVSS30ModifiedAttackVector = "NETWORK"
	// CVSS30ModifiedAttackVectorAdjacentNetwork is a constant for "ADJACENT_NETWORK".
	CVSS30ModifiedAttackVectorAdjacentNetwork CVSS30ModifiedAttackVector = "ADJACENT_NETWORK"
	// CVSS30ModifiedAttackVectorLocal is a constant for "LOCAL".
	CVSS30ModifiedAttackVectorLocal CVSS30ModifiedAttackVector = "LOCAL"
	// CVSS30ModifiedAttackVectorPhysical is a constant for "PHYSICAL".
	CVSS30ModifiedAttackVectorPhysical CVSS30ModifiedAttackVector = "PHYSICAL"
	// CVSS30ModifiedAttackVectorNotDefined is a constant for "NOT_DEFINED".
	CVSS30ModifiedAttackVectorNotDefined CVSS30ModifiedAttackVector = "NOT_DEFINED"
)

var cvss30ModifiedAttackVectorPattern = alternativesUnmarshal(
	string(CVSS30ModifiedAttackVectorNetwork),
	string(CVSS30ModifiedAttackVectorAdjacentNetwork),
	string(CVSS30ModifiedAttackVectorLocal),
	string(CVSS30ModifiedAttackVectorPhysical),
	string(CVSS30ModifiedAttackVectorNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS30ModifiedAttackVector) UnmarshalText(data []byte) error {
	s, err := cvss30ModifiedAttackVectorPattern(data)
	if err == nil {
		*e = CVSS30ModifiedAttackVector(s)
	}
	return err
}

// CVSS30ModifiedCia represents the modifiedCiaType in CVSS30.
type CVSS30ModifiedCia string

const (
	// CVSS30ModifiedCiaNone is a constant for "NONE".
	CVSS30ModifiedCiaNone CVSS30ModifiedCia = "NONE"
	// CVSS30ModifiedCiaLow is a constant for "LOW".
	CVSS30ModifiedCiaLow CVSS30ModifiedCia = "LOW"
	// CVSS30ModifiedCiaHigh is a constant for "HIGH".
	CVSS30ModifiedCiaHigh CVSS30ModifiedCia = "HIGH"
	// CVSS30ModifiedCiaNotDefined is a constant for "NOT_DEFINED".
	CVSS30ModifiedCiaNotDefined CVSS30ModifiedCia = "NOT_DEFINED"
)

var cvss30ModifiedCiaPattern = alternativesUnmarshal(
	string(CVSS30ModifiedCiaNone),
	string(CVSS30ModifiedCiaLow),
	string(CVSS30ModifiedCiaHigh),
	string(CVSS30ModifiedCiaNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS30ModifiedCia) UnmarshalText(data []byte) error {
	s, err := cvss30ModifiedCiaPattern(data)
	if err == nil {
		*e = CVSS30ModifiedCia(s)
	}
	return err
}

// CVSS30ModifiedPrivilegesRequired represents the modifiedPrivilegesRequiredType in CVSS30.
type CVSS30ModifiedPrivilegesRequired string

const (
	// CVSS30ModifiedPrivilegesRequiredHigh is a constant for "HIGH".
	CVSS30ModifiedPrivilegesRequiredHigh CVSS30ModifiedPrivilegesRequired = "HIGH"
	// CVSS30ModifiedPrivilegesRequiredLow is a constant for "LOW".
	CVSS30ModifiedPrivilegesRequiredLow CVSS30ModifiedPrivilegesRequired = "LOW"
	// CVSS30ModifiedPrivilegesRequiredNone is a constant for "NONE".
	CVSS30ModifiedPrivilegesRequiredNone CVSS30ModifiedPrivilegesRequired = "NONE"
	// CVSS30ModifiedPrivilegesRequiredNotDefined is a constant for "NOT_DEFINED".
	CVSS30ModifiedPrivilegesRequiredNotDefined CVSS30ModifiedPrivilegesRequired = "NOT_DEFINED"
)

var cvss30ModifiedPrivilegesRequiredPattern = alternativesUnmarshal(
	string(CVSS30ModifiedPrivilegesRequiredHigh),
	string(CVSS30ModifiedPrivilegesRequiredLow),
	string(CVSS30ModifiedPrivilegesRequiredNone),
	string(CVSS30ModifiedPrivilegesRequiredNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS30ModifiedPrivilegesRequired) UnmarshalText(data []byte) error {
	s, err := cvss30ModifiedPrivilegesRequiredPattern(data)
	if err == nil {
		*e = CVSS30ModifiedPrivilegesRequired(s)
	}
	return err
}

// CVSS30ModifiedScope represents the modifiedScopeType in CVSS30.
type CVSS30ModifiedScope string

const (
	// CVSS30ModifiedScopeUnchanged is a constant for "UNCHANGED".
	CVSS30ModifiedScopeUnchanged CVSS30ModifiedScope = "UNCHANGED"
	// CVSS30ModifiedScopeChanged is a constant for "CHANGED".
	CVSS30ModifiedScopeChanged CVSS30ModifiedScope = "CHANGED"
	// CVSS30ModifiedScopeNotDefined is a constant for "NOT_DEFINED".
	CVSS30ModifiedScopeNotDefined CVSS30ModifiedScope = "NOT_DEFINED"
)

var cvss30ModifiedScopePattern = alternativesUnmarshal(
	string(CVSS30ModifiedScopeUnchanged),
	string(CVSS30ModifiedScopeChanged),
	string(CVSS30ModifiedScopeNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS30ModifiedScope) UnmarshalText(data []byte) error {
	s, err := cvss30ModifiedScopePattern(data)
	if err == nil {
		*e = CVSS30ModifiedScope(s)
	}
	return err
}

// CVSS30ModifiedUserInteraction represents the modifiedUserInteractionType in CVSS30.
type CVSS30ModifiedUserInteraction string

const (
	// CVSS30ModifiedUserInteractionNone is a constant for "NONE".
	CVSS30ModifiedUserInteractionNone CVSS30ModifiedUserInteraction = "NONE"
	// CVSS30ModifiedUserInteractionRequired is a constant for "REQUIRED".
	CVSS30ModifiedUserInteractionRequired CVSS30ModifiedUserInteraction = "REQUIRED"
	// CVSS30ModifiedUserInteractionNotDefined is a constant for "NOT_DEFINED".
	CVSS30ModifiedUserInteractionNotDefined CVSS30ModifiedUserInteraction = "NOT_DEFINED"
)

var cvss30ModifiedUserInteractionPattern = alternativesUnmarshal(
	string(CVSS30ModifiedUserInteractionNone),
	string(CVSS30ModifiedUserInteractionRequired),
	string(CVSS30ModifiedUserInteractionNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS30ModifiedUserInteraction) UnmarshalText(data []byte) error {
	s, err := cvss30ModifiedUserInteractionPattern(data)
	if err == nil {
		*e = CVSS30ModifiedUserInteraction(s)
	}
	return err
}

// CVSS30PrivilegesRequired represents the privilegesRequiredType in CVSS30.
type CVSS30PrivilegesRequired string

const (
	// CVSS30PrivilegesRequiredHigh is a constant for "HIGH".
	CVSS30PrivilegesRequiredHigh CVSS30PrivilegesRequired = "HIGH"
	// CVSS30PrivilegesRequiredLow is a constant for "LOW".
	CVSS30PrivilegesRequiredLow CVSS30PrivilegesRequired = "LOW"
	// CVSS30PrivilegesRequiredNone is a constant for "NONE".
	CVSS30PrivilegesRequiredNone CVSS30PrivilegesRequired = "NONE"
)

var cvss30PrivilegesRequiredPattern = alternativesUnmarshal(
	string(CVSS30PrivilegesRequiredHigh),
	string(CVSS30PrivilegesRequiredLow),
	string(CVSS30PrivilegesRequiredNone),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS30PrivilegesRequired) UnmarshalText(data []byte) error {
	s, err := cvss30PrivilegesRequiredPattern(data)
	if err == nil {
		*e = CVSS30PrivilegesRequired(s)
	}
	return err
}

// CVSS30RemediationLevel represents the remediationLevelType in CVSS30.
type CVSS30RemediationLevel string

const (
	// CVSS30RemediationLevelOfficialFix is a constant for "OFFICIAL_FIX".
	CVSS30RemediationLevelOfficialFix CVSS30RemediationLevel = "OFFICIAL_FIX"
	// CVSS30RemediationLevelTemporaryFix is a constant for "TEMPORARY_FIX".
	CVSS30RemediationLevelTemporaryFix CVSS30RemediationLevel = "TEMPORARY_FIX"
	// CVSS30RemediationLevelWorkaround is a constant for "WORKAROUND".
	CVSS30RemediationLevelWorkaround CVSS30RemediationLevel = "WORKAROUND"
	// CVSS30RemediationLevelUnavailable is a constant for "UNAVAILABLE".
	CVSS30RemediationLevelUnavailable CVSS30RemediationLevel = "UNAVAILABLE"
	// CVSS30RemediationLevelNotDefined is a constant for "NOT_DEFINED".
	CVSS30RemediationLevelNotDefined CVSS30RemediationLevel = "NOT_DEFINED"
)

var cvss30RemediationLevelPattern = alternativesUnmarshal(
	string(CVSS30RemediationLevelOfficialFix),
	string(CVSS30RemediationLevelTemporaryFix),
	string(CVSS30RemediationLevelWorkaround),
	string(CVSS30RemediationLevelUnavailable),
	string(CVSS30RemediationLevelNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS30RemediationLevel) UnmarshalText(data []byte) error {
	s, err := cvss30RemediationLevelPattern(data)
	if err == nil {
		*e = CVSS30RemediationLevel(s)
	}
	return err
}

// CVSS30Scope represents the scopeType in CVSS30.
type CVSS30Scope string

const (
	// CVSS30ScopeUnchanged is a constant for "UNCHANGED".
	CVSS30ScopeUnchanged CVSS30Scope = "UNCHANGED"
	// CVSS30ScopeChanged is a constant for "CHANGED".
	CVSS30ScopeChanged CVSS30Scope = "CHANGED"
)

var cvss30ScopePattern = alternativesUnmarshal(
	string(CVSS30ScopeUnchanged),
	string(CVSS30ScopeChanged),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS30Scope) UnmarshalText(data []byte) error {
	s, err := cvss30ScopePattern(data)
	if err == nil {
		*e = CVSS30Scope(s)
	}
	return err
}

// CVSS30Severity represents the severityType in CVSS30.
type CVSS30Severity string

const (
	// CVSS30SeverityNone is a constant for "NONE".
	CVSS30SeverityNone CVSS30Severity = "NONE"
	// CVSS30SeverityLow is a constant for "LOW".
	CVSS30SeverityLow CVSS30Severity = "LOW"
	// CVSS30SeverityMedium is a constant for "MEDIUM".
	CVSS30SeverityMedium CVSS30Severity = "MEDIUM"
	// CVSS30SeverityHigh is a constant for "HIGH".
	CVSS30SeverityHigh CVSS30Severity = "HIGH"
	// CVSS30SeverityCritical is a constant for "CRITICAL".
	CVSS30SeverityCritical CVSS30Severity = "CRITICAL"
)

var cvss30SeverityPattern = alternativesUnmarshal(
	string(CVSS30SeverityNone),
	string(CVSS30SeverityLow),
	string(CVSS30SeverityMedium),
	string(CVSS30SeverityHigh),
	string(CVSS30SeverityCritical),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS30Severity) UnmarshalText(data []byte) error {
	s, err := cvss30SeverityPattern(data)
	if err == nil {
		*e = CVSS30Severity(s)
	}
	return err
}

// CVSS30UserInteraction represents the userInteractionType in CVSS30.
type CVSS30UserInteraction string

const (
	// CVSS30UserInteractionNone is a constant for "NONE".
	CVSS30UserInteractionNone CVSS30UserInteraction = "NONE"
	// CVSS30UserInteractionRequired is a constant for "REQUIRED".
	CVSS30UserInteractionRequired CVSS30UserInteraction = "REQUIRED"
)

var cvss30UserInteractionPattern = alternativesUnmarshal(
	string(CVSS30UserInteractionNone),
	string(CVSS30UserInteractionRequired),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS30UserInteraction) UnmarshalText(data []byte) error {
	s, err := cvss30UserInteractionPattern(data)
	if err == nil {
		*e = CVSS30UserInteraction(s)
	}
	return err
}
