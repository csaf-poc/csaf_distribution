// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import "testing"

func TestValidationStatusUpdate(t *testing.T) {
	sv := validValidationStatus
	sv.update(invalidValidationStatus)
	sv.update(validValidationStatus)
	if sv != invalidValidationStatus {
		t.Fatalf("got %q expected %q", sv, invalidValidationStatus)
	}
	sv = notValidatedValidationStatus
	sv.update(validValidationStatus)
	sv.update(notValidatedValidationStatus)
	if sv != notValidatedValidationStatus {
		t.Fatalf("got %q expected %q", sv, notValidatedValidationStatus)
	}
}
