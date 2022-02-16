// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import "fmt"

type processor struct {
	cfg *config
}

func (p *processor) process() error {
	for _, p := range p.cfg.Providers {
		fmt.Printf("name '%s' domain: '%s'\n", p.Name, p.Domain)
	}
	return nil
}
