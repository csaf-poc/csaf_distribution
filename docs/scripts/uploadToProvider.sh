#!/usr/bin/env bash
#
# This file is Free Software under the MIT License
# without warranty, see README.md and LICENSES/MIT.txt for details.
#
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>
#
# This script uploads the downloaded csaf examples to the csaf_provider with the help of the csaf_uploader.

./downloadExamples.sh

#TODO FIXME make sure that we do not fall prey to funky filenames
TLPs=("red" "amber" "green" "white")
COUNTER=0
for f in $(ls ~/csaf_examples);
    do
        /$HOME/csaf_tmp/csaf_distribution/csaf_uploader -a upload -t ${TLPs[$COUNTER]} \
        -u https://localhost/cgi-bin/csaf_provider.go --insecure -P security123 \
        --client-cert ~/devca1/testclient1.crt --client-key ~/devca1/testclient1-key.pem \
        ~/csaf_examples/$f;
        let COUNTER++
    done;

