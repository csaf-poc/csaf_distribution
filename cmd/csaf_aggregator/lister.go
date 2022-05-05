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

	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

// mirrorAllowed checks if mirroring is allowed.
func (w *worker) listAllowed() bool {
	var b bool
	return w.expr.Extract(
		`$.list_on_CSAF_aggregators`,
		util.BoolMatcher(&b), w.metadataProvider) == nil && b
}

func (w *worker) lister() (
	*csaf.AggregatorCSAFProvider,
	[]csaf.ProviderURL,
	error,
) {
	// Check if we are allowed to mirror this domain.
	if !w.listAllowed() {
		return nil, nil, fmt.Errorf(
			"no listing of '%s' allowed", w.provider.Name)
	}

	acp, err := w.createAggregatorProvider()
	// No mirroring in lister mode
	return acp, nil, err
}
