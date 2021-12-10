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

type checks []check

func (cs checks) run(domains []string) (*Report, error) {

	var report Report

	for _, d := range domains {
		state := newState(d)
		for _, ch := range cs {
			if err := ch.run(state); err != nil {
				return nil, err
			}
		}
		domain := &Domain{Name: d}
		for _, ch := range cs {
			ch.report(state, domain)
		}
		report.Domains = append(report.Domains, domain)
	}

	return &report, nil
}

type baseCheck struct {
	num         int
	description string
}

type tlsCheck struct {
	baseCheck
}

type redirectsCheck struct {
	baseCheck
}

type providerMetadataCheck struct {
	baseCheck
}

type securityCheck struct {
	baseCheck
}

type wellknownMetadataCheck struct {
	baseCheck
}

type dnsPathCheck struct {
	baseCheck
}

type oneFolderPerYearCheck struct {
	baseCheck
}

type indexCheck struct {
	baseCheck
}

type changesCheck struct {
	baseCheck
}

type directoryListingsCheck struct {
	baseCheck
}

type integrityCheck struct {
	baseCheck
}

type signaturesCheck struct {
	baseCheck
}

type publicPGPKeyCheck struct {
	baseCheck
}

func (bc *baseCheck) report(_ *state, domain *Domain) {
	req := &Requirement{Num: bc.num, Description: bc.description}
	domain.Requirements = append(domain.Requirements, req)
}

func (tc *tlsCheck) run(*state) error {
	// TODO: Implement me!
	return nil
}

func (tc *tlsCheck) report(state *state, domain *Domain) {
	tc.baseCheck.report(state, domain)
	// TODO: Implement me!
}

func (rc *redirectsCheck) run(*state) error {
	// TODO: Implement me!
	return nil
}

func (rc *redirectsCheck) report(state *state, domain *Domain) {
	rc.baseCheck.report(state, domain)
	// TODO: Implement me!
}

func (pmdc *providerMetadataCheck) run(*state) error {
	// TODO: Implement me!
	return nil
}

func (pmdc *providerMetadataCheck) report(state *state, domain *Domain) {
	pmdc.baseCheck.report(state, domain)
	// TODO: Implement me!
}

func (sc *securityCheck) run(*state) error {
	// TODO: Implement me!
	return nil
}

func (sc *securityCheck) report(state *state, domain *Domain) {
	sc.baseCheck.report(state, domain)
	// TODO: Implement me!
}

func (wmdc *wellknownMetadataCheck) run(*state) error {
	// TODO: Implement me!
	return nil
}

func (wmdc *wellknownMetadataCheck) report(state *state, domain *Domain) {
	wmdc.baseCheck.report(state, domain)
	// TODO: Implement me!
}

func (dpc *dnsPathCheck) run(*state) error {
	// TODO: Implement me!
	return nil
}

func (dpc *dnsPathCheck) report(state *state, domain *Domain) {
	dpc.baseCheck.report(state, domain)
	// TODO: Implement me!
}

func (ofpyc *oneFolderPerYearCheck) report(state *state, domain *Domain) {
	ofpyc.baseCheck.report(state, domain)
	// TODO: Implement me!
}

func (ofpyc *oneFolderPerYearCheck) run(*state) error {
	// TODO: Implement me!
	return nil
}

func (ic *indexCheck) report(state *state, domain *Domain) {
	ic.baseCheck.report(state, domain)
	// TODO: Implement me!
}

func (ic *indexCheck) run(*state) error {
	// TODO: Implement me!
	return nil
}

func (cc *changesCheck) report(state *state, domain *Domain) {
	cc.baseCheck.report(state, domain)
	// TODO: Implement me!
}

func (cc *changesCheck) run(*state) error {
	// TODO: Implement me!
	return nil
}

func (dlc *directoryListingsCheck) report(state *state, domain *Domain) {
	dlc.baseCheck.report(state, domain)
	// TODO: Implement me!
}

func (dlc *directoryListingsCheck) run(*state) error {
	// TODO: Implement me!
	return nil
}

func (ic *integrityCheck) report(state *state, domain *Domain) {
	ic.baseCheck.report(state, domain)
	// TODO: Implement me!
}

func (ic *integrityCheck) run(*state) error {
	// TODO: Implement me!
	return nil
}

func (sc *signaturesCheck) report(state *state, domain *Domain) {
	sc.baseCheck.report(state, domain)
	// TODO: Implement me!
}

func (sc *signaturesCheck) run(*state) error {
	// TODO: Implement me!
	return nil
}

func (ppkc *publicPGPKeyCheck) report(state *state, domain *Domain) {
	ppkc.baseCheck.report(state, domain)
	// TODO: Implement me!
}

func (ppkc *publicPGPKeyCheck) run(*state) error {
	// TODO: Implement me!
	return nil
}
