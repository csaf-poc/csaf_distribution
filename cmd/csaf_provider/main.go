// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"log"
	"net/http/cgi"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}

	c, err := newController(cfg)
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}
	pim := newPathInfoMux()
	c.bind(pim)

	if err := cgi.Serve(pim); err != nil {
		log.Fatalf("error: %v\n", err)
	}
}
