// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

// Package csaf contains the core data models used by the csaf distribution.
package csaf

//go:generate go run ./generate_cvss_enums.go -o cvss20enums.go -i ./schema/cvss-v2.0.json -p CVSS20
//go:generate go run ./generate_cvss_enums.go -o cvss30enums.go -i ./schema/cvss-v3.0.json -p CVSS30
//go:generate go run ./generate_cvss_enums.go -o cvss31enums.go -i ./schema/cvss-v3.1.json -p CVSS31
