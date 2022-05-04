// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"errors"

	"github.com/csaf-poc/csaf_distribution/csaf"
)

func (w *worker) lister() (*csaf.AggregatorCSAFProvider, error) {
	// TODO: Implement lister
	return nil, errors.New("not implemented, yet!")
}
