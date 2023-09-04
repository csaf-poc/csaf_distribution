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

// CVSS31AttackComplexity represents the attackComplexityType in CVSS31.
type CVSS31AttackComplexity string

const (
	// CVSS31AttackComplexityHigh is a constant for "HIGH".
	CVSS31AttackComplexityHigh CVSS31AttackComplexity = "HIGH"
	// CVSS31AttackComplexityLow is a constant for "LOW".
	CVSS31AttackComplexityLow CVSS31AttackComplexity = "LOW"
)

var cvss31AttackComplexityPattern = alternativesUnmarshal(
	string(CVSS31AttackComplexityHigh),
	string(CVSS31AttackComplexityLow),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS31AttackComplexity) UnmarshalText(data []byte) error {
	s, err := cvss31AttackComplexityPattern(data)
	if err == nil {
		*e = CVSS31AttackComplexity(s)
	}
	return err
}

// CVSS31AttackVector represents the attackVectorType in CVSS31.
type CVSS31AttackVector string

const (
	// CVSS31AttackVectorNetwork is a constant for "NETWORK".
	CVSS31AttackVectorNetwork CVSS31AttackVector = "NETWORK"
	// CVSS31AttackVectorAdjacentNetwork is a constant for "ADJACENT_NETWORK".
	CVSS31AttackVectorAdjacentNetwork CVSS31AttackVector = "ADJACENT_NETWORK"
	// CVSS31AttackVectorLocal is a constant for "LOCAL".
	CVSS31AttackVectorLocal CVSS31AttackVector = "LOCAL"
	// CVSS31AttackVectorPhysical is a constant for "PHYSICAL".
	CVSS31AttackVectorPhysical CVSS31AttackVector = "PHYSICAL"
)

var cvss31AttackVectorPattern = alternativesUnmarshal(
	string(CVSS31AttackVectorNetwork),
	string(CVSS31AttackVectorAdjacentNetwork),
	string(CVSS31AttackVectorLocal),
	string(CVSS31AttackVectorPhysical),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS31AttackVector) UnmarshalText(data []byte) error {
	s, err := cvss31AttackVectorPattern(data)
	if err == nil {
		*e = CVSS31AttackVector(s)
	}
	return err
}

// CVSS31CiaRequirement represents the ciaRequirementType in CVSS31.
type CVSS31CiaRequirement string

const (
	// CVSS31CiaRequirementLow is a constant for "LOW".
	CVSS31CiaRequirementLow CVSS31CiaRequirement = "LOW"
	// CVSS31CiaRequirementMedium is a constant for "MEDIUM".
	CVSS31CiaRequirementMedium CVSS31CiaRequirement = "MEDIUM"
	// CVSS31CiaRequirementHigh is a constant for "HIGH".
	CVSS31CiaRequirementHigh CVSS31CiaRequirement = "HIGH"
	// CVSS31CiaRequirementNotDefined is a constant for "NOT_DEFINED".
	CVSS31CiaRequirementNotDefined CVSS31CiaRequirement = "NOT_DEFINED"
)

var cvss31CiaRequirementPattern = alternativesUnmarshal(
	string(CVSS31CiaRequirementLow),
	string(CVSS31CiaRequirementMedium),
	string(CVSS31CiaRequirementHigh),
	string(CVSS31CiaRequirementNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS31CiaRequirement) UnmarshalText(data []byte) error {
	s, err := cvss31CiaRequirementPattern(data)
	if err == nil {
		*e = CVSS31CiaRequirement(s)
	}
	return err
}

// CVSS31Cia represents the ciaType in CVSS31.
type CVSS31Cia string

const (
	// CVSS31CiaNone is a constant for "NONE".
	CVSS31CiaNone CVSS31Cia = "NONE"
	// CVSS31CiaLow is a constant for "LOW".
	CVSS31CiaLow CVSS31Cia = "LOW"
	// CVSS31CiaHigh is a constant for "HIGH".
	CVSS31CiaHigh CVSS31Cia = "HIGH"
)

var cvss31CiaPattern = alternativesUnmarshal(
	string(CVSS31CiaNone),
	string(CVSS31CiaLow),
	string(CVSS31CiaHigh),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS31Cia) UnmarshalText(data []byte) error {
	s, err := cvss31CiaPattern(data)
	if err == nil {
		*e = CVSS31Cia(s)
	}
	return err
}

// CVSS31Confidence represents the confidenceType in CVSS31.
type CVSS31Confidence string

const (
	// CVSS31ConfidenceUnknown is a constant for "UNKNOWN".
	CVSS31ConfidenceUnknown CVSS31Confidence = "UNKNOWN"
	// CVSS31ConfidenceReasonable is a constant for "REASONABLE".
	CVSS31ConfidenceReasonable CVSS31Confidence = "REASONABLE"
	// CVSS31ConfidenceConfirmed is a constant for "CONFIRMED".
	CVSS31ConfidenceConfirmed CVSS31Confidence = "CONFIRMED"
	// CVSS31ConfidenceNotDefined is a constant for "NOT_DEFINED".
	CVSS31ConfidenceNotDefined CVSS31Confidence = "NOT_DEFINED"
)

var cvss31ConfidencePattern = alternativesUnmarshal(
	string(CVSS31ConfidenceUnknown),
	string(CVSS31ConfidenceReasonable),
	string(CVSS31ConfidenceConfirmed),
	string(CVSS31ConfidenceNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS31Confidence) UnmarshalText(data []byte) error {
	s, err := cvss31ConfidencePattern(data)
	if err == nil {
		*e = CVSS31Confidence(s)
	}
	return err
}

// CVSS31ExploitCodeMaturity represents the exploitCodeMaturityType in CVSS31.
type CVSS31ExploitCodeMaturity string

const (
	// CVSS31ExploitCodeMaturityUnproven is a constant for "UNPROVEN".
	CVSS31ExploitCodeMaturityUnproven CVSS31ExploitCodeMaturity = "UNPROVEN"
	// CVSS31ExploitCodeMaturityProofOfConcept is a constant for "PROOF_OF_CONCEPT".
	CVSS31ExploitCodeMaturityProofOfConcept CVSS31ExploitCodeMaturity = "PROOF_OF_CONCEPT"
	// CVSS31ExploitCodeMaturityFunctional is a constant for "FUNCTIONAL".
	CVSS31ExploitCodeMaturityFunctional CVSS31ExploitCodeMaturity = "FUNCTIONAL"
	// CVSS31ExploitCodeMaturityHigh is a constant for "HIGH".
	CVSS31ExploitCodeMaturityHigh CVSS31ExploitCodeMaturity = "HIGH"
	// CVSS31ExploitCodeMaturityNotDefined is a constant for "NOT_DEFINED".
	CVSS31ExploitCodeMaturityNotDefined CVSS31ExploitCodeMaturity = "NOT_DEFINED"
)

var cvss31ExploitCodeMaturityPattern = alternativesUnmarshal(
	string(CVSS31ExploitCodeMaturityUnproven),
	string(CVSS31ExploitCodeMaturityProofOfConcept),
	string(CVSS31ExploitCodeMaturityFunctional),
	string(CVSS31ExploitCodeMaturityHigh),
	string(CVSS31ExploitCodeMaturityNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS31ExploitCodeMaturity) UnmarshalText(data []byte) error {
	s, err := cvss31ExploitCodeMaturityPattern(data)
	if err == nil {
		*e = CVSS31ExploitCodeMaturity(s)
	}
	return err
}

// CVSS31ModifiedAttackComplexity represents the modifiedAttackComplexityType in CVSS31.
type CVSS31ModifiedAttackComplexity string

const (
	// CVSS31ModifiedAttackComplexityHigh is a constant for "HIGH".
	CVSS31ModifiedAttackComplexityHigh CVSS31ModifiedAttackComplexity = "HIGH"
	// CVSS31ModifiedAttackComplexityLow is a constant for "LOW".
	CVSS31ModifiedAttackComplexityLow CVSS31ModifiedAttackComplexity = "LOW"
	// CVSS31ModifiedAttackComplexityNotDefined is a constant for "NOT_DEFINED".
	CVSS31ModifiedAttackComplexityNotDefined CVSS31ModifiedAttackComplexity = "NOT_DEFINED"
)

var cvss31ModifiedAttackComplexityPattern = alternativesUnmarshal(
	string(CVSS31ModifiedAttackComplexityHigh),
	string(CVSS31ModifiedAttackComplexityLow),
	string(CVSS31ModifiedAttackComplexityNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS31ModifiedAttackComplexity) UnmarshalText(data []byte) error {
	s, err := cvss31ModifiedAttackComplexityPattern(data)
	if err == nil {
		*e = CVSS31ModifiedAttackComplexity(s)
	}
	return err
}

// CVSS31ModifiedAttackVector represents the modifiedAttackVectorType in CVSS31.
type CVSS31ModifiedAttackVector string

const (
	// CVSS31ModifiedAttackVectorNetwork is a constant for "NETWORK".
	CVSS31ModifiedAttackVectorNetwork CVSS31ModifiedAttackVector = "NETWORK"
	// CVSS31ModifiedAttackVectorAdjacentNetwork is a constant for "ADJACENT_NETWORK".
	CVSS31ModifiedAttackVectorAdjacentNetwork CVSS31ModifiedAttackVector = "ADJACENT_NETWORK"
	// CVSS31ModifiedAttackVectorLocal is a constant for "LOCAL".
	CVSS31ModifiedAttackVectorLocal CVSS31ModifiedAttackVector = "LOCAL"
	// CVSS31ModifiedAttackVectorPhysical is a constant for "PHYSICAL".
	CVSS31ModifiedAttackVectorPhysical CVSS31ModifiedAttackVector = "PHYSICAL"
	// CVSS31ModifiedAttackVectorNotDefined is a constant for "NOT_DEFINED".
	CVSS31ModifiedAttackVectorNotDefined CVSS31ModifiedAttackVector = "NOT_DEFINED"
)

var cvss31ModifiedAttackVectorPattern = alternativesUnmarshal(
	string(CVSS31ModifiedAttackVectorNetwork),
	string(CVSS31ModifiedAttackVectorAdjacentNetwork),
	string(CVSS31ModifiedAttackVectorLocal),
	string(CVSS31ModifiedAttackVectorPhysical),
	string(CVSS31ModifiedAttackVectorNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS31ModifiedAttackVector) UnmarshalText(data []byte) error {
	s, err := cvss31ModifiedAttackVectorPattern(data)
	if err == nil {
		*e = CVSS31ModifiedAttackVector(s)
	}
	return err
}

// CVSS31ModifiedCia represents the modifiedCiaType in CVSS31.
type CVSS31ModifiedCia string

const (
	// CVSS31ModifiedCiaNone is a constant for "NONE".
	CVSS31ModifiedCiaNone CVSS31ModifiedCia = "NONE"
	// CVSS31ModifiedCiaLow is a constant for "LOW".
	CVSS31ModifiedCiaLow CVSS31ModifiedCia = "LOW"
	// CVSS31ModifiedCiaHigh is a constant for "HIGH".
	CVSS31ModifiedCiaHigh CVSS31ModifiedCia = "HIGH"
	// CVSS31ModifiedCiaNotDefined is a constant for "NOT_DEFINED".
	CVSS31ModifiedCiaNotDefined CVSS31ModifiedCia = "NOT_DEFINED"
)

var cvss31ModifiedCiaPattern = alternativesUnmarshal(
	string(CVSS31ModifiedCiaNone),
	string(CVSS31ModifiedCiaLow),
	string(CVSS31ModifiedCiaHigh),
	string(CVSS31ModifiedCiaNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS31ModifiedCia) UnmarshalText(data []byte) error {
	s, err := cvss31ModifiedCiaPattern(data)
	if err == nil {
		*e = CVSS31ModifiedCia(s)
	}
	return err
}

// CVSS31ModifiedPrivilegesRequired represents the modifiedPrivilegesRequiredType in CVSS31.
type CVSS31ModifiedPrivilegesRequired string

const (
	// CVSS31ModifiedPrivilegesRequiredHigh is a constant for "HIGH".
	CVSS31ModifiedPrivilegesRequiredHigh CVSS31ModifiedPrivilegesRequired = "HIGH"
	// CVSS31ModifiedPrivilegesRequiredLow is a constant for "LOW".
	CVSS31ModifiedPrivilegesRequiredLow CVSS31ModifiedPrivilegesRequired = "LOW"
	// CVSS31ModifiedPrivilegesRequiredNone is a constant for "NONE".
	CVSS31ModifiedPrivilegesRequiredNone CVSS31ModifiedPrivilegesRequired = "NONE"
	// CVSS31ModifiedPrivilegesRequiredNotDefined is a constant for "NOT_DEFINED".
	CVSS31ModifiedPrivilegesRequiredNotDefined CVSS31ModifiedPrivilegesRequired = "NOT_DEFINED"
)

var cvss31ModifiedPrivilegesRequiredPattern = alternativesUnmarshal(
	string(CVSS31ModifiedPrivilegesRequiredHigh),
	string(CVSS31ModifiedPrivilegesRequiredLow),
	string(CVSS31ModifiedPrivilegesRequiredNone),
	string(CVSS31ModifiedPrivilegesRequiredNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS31ModifiedPrivilegesRequired) UnmarshalText(data []byte) error {
	s, err := cvss31ModifiedPrivilegesRequiredPattern(data)
	if err == nil {
		*e = CVSS31ModifiedPrivilegesRequired(s)
	}
	return err
}

// CVSS31ModifiedScope represents the modifiedScopeType in CVSS31.
type CVSS31ModifiedScope string

const (
	// CVSS31ModifiedScopeUnchanged is a constant for "UNCHANGED".
	CVSS31ModifiedScopeUnchanged CVSS31ModifiedScope = "UNCHANGED"
	// CVSS31ModifiedScopeChanged is a constant for "CHANGED".
	CVSS31ModifiedScopeChanged CVSS31ModifiedScope = "CHANGED"
	// CVSS31ModifiedScopeNotDefined is a constant for "NOT_DEFINED".
	CVSS31ModifiedScopeNotDefined CVSS31ModifiedScope = "NOT_DEFINED"
)

var cvss31ModifiedScopePattern = alternativesUnmarshal(
	string(CVSS31ModifiedScopeUnchanged),
	string(CVSS31ModifiedScopeChanged),
	string(CVSS31ModifiedScopeNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS31ModifiedScope) UnmarshalText(data []byte) error {
	s, err := cvss31ModifiedScopePattern(data)
	if err == nil {
		*e = CVSS31ModifiedScope(s)
	}
	return err
}

// CVSS31ModifiedUserInteraction represents the modifiedUserInteractionType in CVSS31.
type CVSS31ModifiedUserInteraction string

const (
	// CVSS31ModifiedUserInteractionNone is a constant for "NONE".
	CVSS31ModifiedUserInteractionNone CVSS31ModifiedUserInteraction = "NONE"
	// CVSS31ModifiedUserInteractionRequired is a constant for "REQUIRED".
	CVSS31ModifiedUserInteractionRequired CVSS31ModifiedUserInteraction = "REQUIRED"
	// CVSS31ModifiedUserInteractionNotDefined is a constant for "NOT_DEFINED".
	CVSS31ModifiedUserInteractionNotDefined CVSS31ModifiedUserInteraction = "NOT_DEFINED"
)

var cvss31ModifiedUserInteractionPattern = alternativesUnmarshal(
	string(CVSS31ModifiedUserInteractionNone),
	string(CVSS31ModifiedUserInteractionRequired),
	string(CVSS31ModifiedUserInteractionNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS31ModifiedUserInteraction) UnmarshalText(data []byte) error {
	s, err := cvss31ModifiedUserInteractionPattern(data)
	if err == nil {
		*e = CVSS31ModifiedUserInteraction(s)
	}
	return err
}

// CVSS31PrivilegesRequired represents the privilegesRequiredType in CVSS31.
type CVSS31PrivilegesRequired string

const (
	// CVSS31PrivilegesRequiredHigh is a constant for "HIGH".
	CVSS31PrivilegesRequiredHigh CVSS31PrivilegesRequired = "HIGH"
	// CVSS31PrivilegesRequiredLow is a constant for "LOW".
	CVSS31PrivilegesRequiredLow CVSS31PrivilegesRequired = "LOW"
	// CVSS31PrivilegesRequiredNone is a constant for "NONE".
	CVSS31PrivilegesRequiredNone CVSS31PrivilegesRequired = "NONE"
)

var cvss31PrivilegesRequiredPattern = alternativesUnmarshal(
	string(CVSS31PrivilegesRequiredHigh),
	string(CVSS31PrivilegesRequiredLow),
	string(CVSS31PrivilegesRequiredNone),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS31PrivilegesRequired) UnmarshalText(data []byte) error {
	s, err := cvss31PrivilegesRequiredPattern(data)
	if err == nil {
		*e = CVSS31PrivilegesRequired(s)
	}
	return err
}

// CVSS31RemediationLevel represents the remediationLevelType in CVSS31.
type CVSS31RemediationLevel string

const (
	// CVSS31RemediationLevelOfficialFix is a constant for "OFFICIAL_FIX".
	CVSS31RemediationLevelOfficialFix CVSS31RemediationLevel = "OFFICIAL_FIX"
	// CVSS31RemediationLevelTemporaryFix is a constant for "TEMPORARY_FIX".
	CVSS31RemediationLevelTemporaryFix CVSS31RemediationLevel = "TEMPORARY_FIX"
	// CVSS31RemediationLevelWorkaround is a constant for "WORKAROUND".
	CVSS31RemediationLevelWorkaround CVSS31RemediationLevel = "WORKAROUND"
	// CVSS31RemediationLevelUnavailable is a constant for "UNAVAILABLE".
	CVSS31RemediationLevelUnavailable CVSS31RemediationLevel = "UNAVAILABLE"
	// CVSS31RemediationLevelNotDefined is a constant for "NOT_DEFINED".
	CVSS31RemediationLevelNotDefined CVSS31RemediationLevel = "NOT_DEFINED"
)

var cvss31RemediationLevelPattern = alternativesUnmarshal(
	string(CVSS31RemediationLevelOfficialFix),
	string(CVSS31RemediationLevelTemporaryFix),
	string(CVSS31RemediationLevelWorkaround),
	string(CVSS31RemediationLevelUnavailable),
	string(CVSS31RemediationLevelNotDefined),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS31RemediationLevel) UnmarshalText(data []byte) error {
	s, err := cvss31RemediationLevelPattern(data)
	if err == nil {
		*e = CVSS31RemediationLevel(s)
	}
	return err
}

// CVSS31Scope represents the scopeType in CVSS31.
type CVSS31Scope string

const (
	// CVSS31ScopeUnchanged is a constant for "UNCHANGED".
	CVSS31ScopeUnchanged CVSS31Scope = "UNCHANGED"
	// CVSS31ScopeChanged is a constant for "CHANGED".
	CVSS31ScopeChanged CVSS31Scope = "CHANGED"
)

var cvss31ScopePattern = alternativesUnmarshal(
	string(CVSS31ScopeUnchanged),
	string(CVSS31ScopeChanged),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS31Scope) UnmarshalText(data []byte) error {
	s, err := cvss31ScopePattern(data)
	if err == nil {
		*e = CVSS31Scope(s)
	}
	return err
}

// CVSS31Severity represents the severityType in CVSS31.
type CVSS31Severity string

const (
	// CVSS31SeverityNone is a constant for "NONE".
	CVSS31SeverityNone CVSS31Severity = "NONE"
	// CVSS31SeverityLow is a constant for "LOW".
	CVSS31SeverityLow CVSS31Severity = "LOW"
	// CVSS31SeverityMedium is a constant for "MEDIUM".
	CVSS31SeverityMedium CVSS31Severity = "MEDIUM"
	// CVSS31SeverityHigh is a constant for "HIGH".
	CVSS31SeverityHigh CVSS31Severity = "HIGH"
	// CVSS31SeverityCritical is a constant for "CRITICAL".
	CVSS31SeverityCritical CVSS31Severity = "CRITICAL"
)

var cvss31SeverityPattern = alternativesUnmarshal(
	string(CVSS31SeverityNone),
	string(CVSS31SeverityLow),
	string(CVSS31SeverityMedium),
	string(CVSS31SeverityHigh),
	string(CVSS31SeverityCritical),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS31Severity) UnmarshalText(data []byte) error {
	s, err := cvss31SeverityPattern(data)
	if err == nil {
		*e = CVSS31Severity(s)
	}
	return err
}

// CVSS31UserInteraction represents the userInteractionType in CVSS31.
type CVSS31UserInteraction string

const (
	// CVSS31UserInteractionNone is a constant for "NONE".
	CVSS31UserInteractionNone CVSS31UserInteraction = "NONE"
	// CVSS31UserInteractionRequired is a constant for "REQUIRED".
	CVSS31UserInteractionRequired CVSS31UserInteraction = "REQUIRED"
)

var cvss31UserInteractionPattern = alternativesUnmarshal(
	string(CVSS31UserInteractionNone),
	string(CVSS31UserInteractionRequired),
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *CVSS31UserInteraction) UnmarshalText(data []byte) error {
	s, err := cvss31UserInteractionPattern(data)
	if err == nil {
		*e = CVSS31UserInteraction(s)
	}
	return err
}
