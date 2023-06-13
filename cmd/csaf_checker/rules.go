// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"sort"

	"github.com/csaf-poc/csaf_distribution/v2/csaf"
)

type ruleCondition int

const (
	condAll ruleCondition = iota
	condOneOf
)

type requirementRules struct {
	cond      ruleCondition
	satisfies int
	subs      []*requirementRules
}

var (
	publisherRules = &requirementRules{
		cond: condAll,
		subs: ruleAtoms(1, 2, 3 /* 4 */),
	}

	providerRules = &requirementRules{
		cond: condAll,
		subs: []*requirementRules{
			publisherRules,
			{cond: condOneOf, subs: ruleAtoms(8, 9, 10)},
			{cond: condOneOf, subs: []*requirementRules{
				{cond: condAll, subs: ruleAtoms(11, 12, 13, 14)},
				{cond: condAll, subs: ruleAtoms(15, 16, 17)},
			}},
		},
	}

	trustedProviderRules = &requirementRules{
		cond: condAll,
		subs: []*requirementRules{
			providerRules,
			{cond: condAll, subs: ruleAtoms(18, 19, 20)},
		},
	}
)

func ruleAtoms(nums ...int) []*requirementRules {
	rules := make([]*requirementRules, len(nums))
	for i, num := range nums {
		rules[i] = &requirementRules{
			cond:      condAll,
			satisfies: num,
		}
	}
	return rules
}

func (rules *requirementRules) reporters() []reporter {
	if rules == nil {
		return nil
	}
	var nums []int

	var recurse func(*requirementRules)
	recurse = func(rules *requirementRules) {
		if rules.satisfies != 0 {
			// There should not be any dupes
			for _, n := range nums {
				if n == rules.satisfies {
					goto doRecurse
				}
			}
			nums = append(nums, rules.satisfies)
		}
	doRecurse:
		for _, sub := range rules.subs {
			recurse(sub)
		}
	}
	recurse(rules)

	sort.Ints(nums)

	reps := make([]reporter, len(nums))

	for i, n := range nums {
		reps[i] = reporters[n]
	}
	return reps
}

// roleRequirements returns the rules for the given role.
func roleRequirements(role csaf.MetadataRole) *requirementRules {
	switch role {
	case csaf.MetadataRoleTrustedProvider:
		return trustedProviderRules
	case csaf.MetadataRoleProvider:
		return providerRules
	case csaf.MetadataRolePublisher:
		return publisherRules
	default:
		return nil
	}
}
