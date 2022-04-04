#!/usr/bin/env bash
#
# Desc: Tries getting csaf 2.0 examples from api.github, do not run too often.
#
# This file is Free Software under the MIT License
# without warranty, see README.md and LICENSES/MIT.txt for details.
#
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>
pushd ~
curl --silent --show-error -H 'Accept: application/vnd.github.v3.raw' \
 https://api.github.com/repos/oasis-tcs/csaf/contents/csaf_2.0/examples/csaf \
 | grep '"path":' |  sed -e 's/".*": "\(.*\)",/\1/' \
 > csaf_examples_pathnames.txt

mkdir csaf_examples
cd csaf_examples

# careful with automation here, in theory lines in
# ../csaf_examples_pathnames.txt could contain anything, because the json
# objects are controlled by the file names in that directory and the gitup api
cat ../csaf_examples_pathnames.txt | \
 xargs -I {} \
  curl --silent --show-error -H 'Accept: application/vnd.github.v3.raw' \
   https://api.github.com/repos/oasis-tcs/csaf/contents/{} -O

popd
