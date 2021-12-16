// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package util

import (
	"encoding/json"
)

// ReMarshalJSON transforms data from src to dst via JSON marshalling.
func ReMarshalJSON(dst, src interface{}) error {
	intermediate, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(intermediate, dst)
}
