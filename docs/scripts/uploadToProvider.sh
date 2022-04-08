#!/usr/bin/env bash
#
# Desc: Call ./downloadExamples.sh and then try csaf_uploader.
#
# This file is Free Software under the MIT License
# without warranty, see README.md and LICENSES/MIT.txt for details.
#
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

set -e


# assumes that the following script only downloads file with filenames
# following https://docs.oasis-open.org/csaf/csaf/v2.0/cs01/csaf-v2.0-cs01.html#51-filename
# which are save to process further
./downloadExamples.sh

TLPs=("white" "green" "amber" "red")
COUNTER=0
for f in $(ls csaf_examples);
    do
        ../../bin-linux-amd64/csaf_uploader -a upload -t ${TLPs[$COUNTER]} \
        -u https://localhost:8443/cgi-bin/csaf_provider.go --insecure -P security123 \
        --client-cert ~/devca1/testclient1.crt --client-key ~/devca1/testclient1-key.pem \
        ./csaf_examples/"$f";
        let COUNTER++
    done;
