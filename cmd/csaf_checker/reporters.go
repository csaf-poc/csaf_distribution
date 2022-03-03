// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

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
	tlsReporter               struct{ baseReporter }
	redirectsReporter         struct{ baseReporter }
	providerMetadataReport    struct{ baseReporter }
	securityReporter          struct{ baseReporter }
	wellknownMetadataReporter struct{ baseReporter }
	dnsPathReporter           struct{ baseReporter }
	oneFolderPerYearReport    struct{ baseReporter }
	indexReporter             struct{ baseReporter }
	changesReporter           struct{ baseReporter }
	directoryListingsReporter struct{ baseReporter }
	integrityReporter         struct{ baseReporter }
	signaturesReporter        struct{ baseReporter }
	publicPGPKeyReporter      struct{ baseReporter }
)

func (bc *baseReporter) requirement(domain *Domain) *Requirement {
	req := &Requirement{
		Num:         bc.num,
		Description: bc.description,
	}
	domain.Requirements = append(domain.Requirements, req)
	return req
}

func (r *tlsReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if p.noneTLS == nil {
		req.message("No TLS checks performed.")
		return
	}
	if len(p.noneTLS) == 0 {
		req.message("All tested URLs were HTTPS.")
		return
	}

	urls := make([]string, len(p.noneTLS))
	var i int
	for k := range p.noneTLS {
		urls[i] = k
		i++
	}
	sort.Strings(urls)
	req.message("Following non-HTTPS URLs were used:")
	req.message(urls...)
}

func (r *redirectsReporter) report(p *processor, domain *Domain) {
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
	if !used(p.badProviderMetadatas) {
		req.message("No provider-metadata.json checked.")
		return
	}
	if len(p.badProviderMetadatas) == 0 {
		req.message("Found good provider metadata.")
		return
	}
	req.Messages = p.badProviderMetadatas
}

func (r *securityReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !used(p.badSecurities) {
		req.message("No security.txt checked.")
		return
	}
	if len(p.badSecurities) == 0 {
		req.message("Found good security.txt.")
		return
	}
	req.Messages = p.badSecurities
}

func (r *wellknownMetadataReporter) report(_ *processor, domain *Domain) {
	// TODO: Implement me!
	req := r.requirement(domain)
	req.message("(Not checked, missing implementation.)")
}

func (r *dnsPathReporter) report(_ *processor, domain *Domain) {
	// TODO: Implement me!
	req := r.requirement(domain)
	req.message("(Not checked, missing implementation.)")
}

func (r *oneFolderPerYearReport) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !used(p.badFolders) {
		req.message("No checks if files are in right folders were performed.")
		return
	}
	if len(p.badFolders) == 0 {
		req.message("All CSAF files are in the right folders.")
		return
	}
	req.Messages = p.badFolders
}

func (r *indexReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !used(p.badIndices) {
		req.message("No index.txt checked.")
		return
	}
	if len(p.badIndices) == 0 {
		req.message("Found good index.txt.")
		return
	}
	req.Messages = p.badIndices
}

func (r *changesReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !used(p.badChanges) {
		req.message("No changes.csv checked.")
		return
	}
	if len(p.badChanges) == 0 {
		req.message("Found good changes.csv.")
		return
	}
	req.Messages = p.badChanges
}

func (r *directoryListingsReporter) report(_ *processor, domain *Domain) {
	// TODO: Implement me!
	req := r.requirement(domain)
	_ = req
}

func (r *integrityReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !used(p.badIntegrities) {
		req.message("No checksums checked.")
		return
	}
	if len(p.badIntegrities) == 0 {
		req.message("All checksums match.")
		return
	}
	req.Messages = p.badIntegrities
}

func (r *signaturesReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !used(p.badSignatures) {
		req.message("No signatures checked.")
		return
	}
	req.Messages = p.badSignatures
	if len(p.badSignatures) == 0 {
		req.message("All signatures verified.")
	}
}

func (r *publicPGPKeyReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !used(p.badPGPs) {
		req.message("No public OpenPGP keys loaded.")
		return
	}
	req.Messages = p.badPGPs
	if len(p.keys) > 0 {
		req.message(fmt.Sprintf("%d public OpenPGP key(s) loaded.", len(p.keys)))
	}
}
