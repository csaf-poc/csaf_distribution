// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

type state struct {
	domain string
}

func newState(domain string) *state {
	return &state{domain: domain}
}

type check interface {
	run(*state) error
	report(*state, *Domain)
}

func run(domains []string, checks []check) (*Report, error) {

	var report Report

	for _, d := range domains {
		state := newState(d)
		for _, ch := range checks {
			if err := ch.run(state); err != nil {
				return nil, err
			}
		}
		domain := new(Domain)
		for _, ch := range checks {
			ch.report(state, domain)
		}
		report.Domains = append(report.Domains, domain)
	}

	return &report, nil
}
