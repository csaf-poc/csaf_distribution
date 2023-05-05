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
	"strings"
)

type (
	baseReporter struct {
		num         int
		description string
	}
	validReporter             struct{ baseReporter }
	filenameReporter          struct{ baseReporter }
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

// contains returns whether any of vs is present in s.
func containsAny[E comparable](s []E, vs ...E) bool {
	for _, e := range s {
		for _, v := range vs {
			if e == v {
				return true
			}
		}
	}
	return false
}

// report reports if there where any invalid filenames,
func (r *validReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if p.validator == nil {
		req.message(WarnType, "No remote validator configured")
	}
	switch {
	case !p.invalidAdvisories.used():
		req.message(InfoType, "No validations performed")
	case len(p.invalidAdvisories) == 0:
		if p.validator != nil && containsAny(p.opts.RemoteValidatorPresets,
			"basic", "mandatory", "extended", "full") {
			req.message(InfoType, "All advisories validated fine.")
		} else {
			req.message(InfoType, "All advisories validated fine against the schema.")
		}
	default:
		req.Append(p.invalidAdvisories)
	}
}

// report reports if there where any bad filename.
func (r *filenameReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badFilenames.used() {
		req.message(InfoType, "No filenames checked for conformance")
	} else if len(p.badFilenames) == 0 {
		req.message(InfoType, "All found filenames are conforming.")
	} else {
		req.Append(p.badFilenames)
	}
}

// report tests if the URLs are HTTPS and sets the "message" field value
// of the "Requirement" struct as a result of that.
// A list of non HTTPS URLs is included in the value of the "message" field.
func (r *tlsReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if p.noneTLS == nil {
		req.message(InfoType, "No TLS checks performed.")
		return
	}
	if len(p.noneTLS) == 0 {
		req.message(InfoType, "All tested URLs were HTTPS.")
		return
	}

	urls := make([]string, len(p.noneTLS))
	var i int
	for k := range p.noneTLS {
		urls[i] = k
		i++
	}
	sort.Strings(urls)
	req.message(ErrorType, "Following non-HTTPS URLs were used:")
	req.message(ErrorType, urls...)
}

// report tests if redirects are used and sets the "message" field value
// of the "Requirement" struct as a result of that.
func (r *redirectsReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if len(p.redirects) == 0 {
		req.message(InfoType, "No redirections found.")
		return
	}

	keys := keysNotInValues(p.redirects)

	first := func(i int) string {
		if vs := p.redirects[keys[i]]; len(vs) > 0 {
			return vs[0]
		}
		return ""
	}

	sort.Slice(keys, func(i, j int) bool { return first(i) < first(j) })

	for i, k := range keys {
		keys[i] = fmt.Sprintf("Redirect %s -> %s", strings.Join(p.redirects[k], " -> "), k)
	}
	req.message(WarnType, keys...)
}

// keysNotInValues returns a slice of keys which are not in the values
// of the given map.
func keysNotInValues(m map[string][]string) []string {
	values := map[string]bool{}
	for _, vs := range m {
		for _, v := range vs {
			values[v] = true
		}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		if !values[k] {
			keys = append(keys, k)
		}
	}
	return keys
}

// report tests if an provider-metadata.json are available and sets the
// "message" field value of the "Requirement" struct as a result of that.
func (r *providerMetadataReport) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badProviderMetadata.used() {
		req.message(InfoType, "No provider-metadata.json checked.")
		return
	}
	if len(p.badProviderMetadata) == 0 {
		req.message(InfoType, "Found good provider metadata.")
		return
	}
	req.Messages = p.badProviderMetadata
}

// report tests the "security.txt" file and sets the "message" field value
// of the "Requirement" struct as a result of that.
func (r *securityReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badSecurity.used() {
		req.message(InfoType, "Performed no in-depth test of security.txt.")
		return
	}
	if len(p.badSecurity) == 0 {
		req.message(InfoType, "Found CSAF entry in security.txt.")
		return
	}
	req.Messages = p.badSecurity
}

// report tests the availability of the "provider-metadata.json" under /.well-known/csaf/ directoy.
func (r *wellknownMetadataReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badWellknownMetadata.used() {
		req.message(InfoType, "Since no valid provider-metadata.json was found, no extended check was performed.")
		return
	}
	if len(p.badWellknownMetadata) == 0 {
		req.message(InfoType, "Found /.well-known/csaf/provider-metadata.json")
		return
	}
	req.Messages = p.badWellknownMetadata
}

// report outputs the result of the the explicit DNS test.
func (r *dnsPathReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badDNSPath.used() {
		req.message(InfoType, "No check about contents from https://csaf.data.security.DOMAIN performed.")
		return
	}
	if len(p.badDNSPath) == 0 {
		req.message(InfoType, "https://csaf.data.security.DOMAIN is available and serves the provider-metadata.json.")
		return
	}
	req.Messages = p.badDNSPath
}

func (r *oneFolderPerYearReport) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badFolders.used() {
		req.message(InfoType, "No checks if files are in right folders were performed.")
		return
	}
	if len(p.badFolders) == 0 {
		req.message(InfoType, "All CSAF files are in the right folders.")
		return
	}
	req.Messages = p.badFolders
}

func (r *indexReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badIndices.used() {
		req.message(InfoType, "No index.txt checked.")
		return
	}
	if len(p.badIndices) == 0 {
		req.message(InfoType, "Found good index.txt.")
		return
	}
	req.Messages = p.badIndices
}

func (r *changesReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badChanges.used() {
		req.message(InfoType, "No changes.csv checked.")
		return
	}
	if len(p.badChanges) == 0 {
		req.message(InfoType, "Found good changes.csv.")
		return
	}
	req.Messages = p.badChanges
}

func (r *directoryListingsReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badDirListings.used() {
		req.message(InfoType, "No directory listings checked.")
		return
	}
	if len(p.badDirListings) == 0 {
		req.message(InfoType, "All directory listings are valid.")
		return
	}
	req.Messages = p.badDirListings
}

func (r *integrityReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badIntegrities.used() {
		req.message(InfoType, "No checksums checked.")
		return
	}
	if len(p.badIntegrities) == 0 {
		req.message(InfoType, "All checksums match.")
		return
	}
	req.Messages = p.badIntegrities
}

func (r *signaturesReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badSignatures.used() {
		req.message(InfoType, "No signatures checked.")
		return
	}
	req.Messages = p.badSignatures
	if len(p.badSignatures) == 0 {
		req.message(InfoType, "All signatures verified.")
	}
}

func (r *publicPGPKeyReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badPGPs.used() {
		req.message(InfoType, "No public OpenPGP keys loaded.")
		return
	}
	req.Messages = p.badPGPs
	if p.keys != nil {
		req.message(InfoType, fmt.Sprintf("%d public OpenPGP key(s) loaded.",
			p.keys.CountEntities()))
	}
}
