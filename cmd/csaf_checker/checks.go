// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"sort"
)

type (
	baseReporter struct {
		num         int
		description string
	}
	tlsReport               struct{ baseReporter }
	redirectsReport         struct{ baseReporter }
	providerMetadataReport  struct{ baseReporter }
	securityReport          struct{ baseReporter }
	wellknownMetadataReport struct{ baseReporter }
	dnsPathReport           struct{ baseReporter }
	oneFolderPerYearReport  struct{ baseReporter }
	indexReport             struct{ baseReporter }
	changesReport           struct{ baseReporter }
	directoryListingsReport struct{ baseReporter }
	integrityReport         struct{ baseReporter }
	signaturesReport        struct{ baseReporter }
	publicPGPKeyReport      struct{ baseReporter }
)

func (bc *baseReporter) requirement(domain *Domain) *Requirement {
	req := &Requirement{
		Num:         bc.num,
		Description: bc.description,
	}
	domain.Requirements = append(domain.Requirements, req)
	return req
}

func (r *tlsReport) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if len(p.noneTLS) == 0 {
		req.message("All tested URLs were https.")
		return
	}

	urls := make([]string, len(p.noneTLS))
	var i int
	for k := range p.noneTLS {
		urls[i] = k
		i++
	}
	sort.Strings(urls)
	req.message("Following none https URLs were used:")
	req.message(urls...)
}

func (r *redirectsReport) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if len(p.redirects) == 0 {
		req.message("No redirections found.")
		return
	}

	keys := make([]string, len(p.redirects))
	var i int
	for k := range p.redirects {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	for i, k := range keys {
		keys[i] = fmt.Sprintf("Redirect %s: %s", k, p.redirects[k])
	}
	req.Messages = keys
}

func (r *providerMetadataReport) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if len(p.badProviderMetadatas) == 0 {
		req.message("No problems with provider metadata.")
		return
	}
	req.Messages = p.badProviderMetadatas
}

func (r *securityReport) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if len(p.badSecurity) == 0 {
		req.message("No problems with security.txt.")
		return
	}
	req.Messages = p.badSecurity
}

func (r *wellknownMetadataReport) report(_ *processor, domain *Domain) {
	// TODO: Implement me!
	req := r.requirement(domain)
	_ = req
}

func (r *dnsPathReport) report(_ *processor, domain *Domain) {
	// TODO: Implement me!
	req := r.requirement(domain)
	_ = req
}

func (r *oneFolderPerYearReport) report(_ *processor, domain *Domain) {
	// TODO: Implement me!
	req := r.requirement(domain)
	_ = req
}

func (r *indexReport) report(_ *processor, domain *Domain) {
	// TODO: Implement me!
	req := r.requirement(domain)
	_ = req
}

func (r *changesReport) report(_ *processor, domain *Domain) {
	// TODO: Implement me!
	req := r.requirement(domain)
	_ = req
}

func (r *directoryListingsReport) report(_ *processor, domain *Domain) {
	// TODO: Implement me!
	req := r.requirement(domain)
	_ = req
}

func (r *integrityReport) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if len(p.badHashes) == 0 {
		req.message("All checksums match.")
		return
	}
	req.Messages = p.badHashes
}

func (r *signaturesReport) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if len(p.badSignatures) == 0 {
		req.message("All signatures verified.")
	}
	req.Messages = p.badSignatures
}

func (r *publicPGPKeyReport) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	req.Messages = p.badPGPs
	if len(p.keys) > 0 {
		req.message(fmt.Sprintf("%d PGP key(s) loaded successfully.", len(p.keys)))
	}
}
