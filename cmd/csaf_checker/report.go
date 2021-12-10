// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

// Requirement a single requirement report of a domain.
type Requirement struct {
	Num         int      `json:"num"`
	Description string   `json:"description"`
	Messages    []string `json:"messages,omitempty"`
}

// Domain are the results of a domain.
type Domain struct {
	Name         string         `json:"name"`
	Requirements []*Requirement `json:"requirements,omitempty"`
}

// Report is the overall report.
type Report struct {
	Domains []*Domain `json:"domains,omitempty"`
}
