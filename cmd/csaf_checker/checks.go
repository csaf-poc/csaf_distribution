package main

type state struct {
	domain string
}

func newState(domain string) *state {
	return &state{domain: domain}
}

type check interface {
	run(*state) error
	report(*state, *Domain)
}

func run(domains []string, checks []check) (*Report, error) {

	var report Report

	for _, d := range domains {
		state := newState(d)
		for _, ch := range checks {
			if err := ch.run(state); err != nil {
				return nil, err
			}
		}
		domain := new(Domain)
		for _, ch := range checks {
			ch.report(state, domain)
		}
		report.Domains = append(report.Domains, domain)
	}

	return &report, nil
}
