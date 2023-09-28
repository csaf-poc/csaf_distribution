// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package misc

import (
	"io"
	"mime/multipart"
	"testing"
)

// TestCreateFormFile tests if CreateFormFile throws an error when creating
// a FormFile
func TestCreateFormFile(t *testing.T) {
	writer := multipart.NewWriter(io.Discard)

	if _, err := CreateFormFile(writer, "csaf", "data", "application/json"); err != nil {
		t.Errorf("Failure: failed to create an io.Writer via CreateFormFile")
	}
}
