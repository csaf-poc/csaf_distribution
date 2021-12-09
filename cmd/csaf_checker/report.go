package main

// Requirement a single requirement report of a domain.
type Requirement struct {
	Num         int      `json:"num"`
	Description string   `json:"description"`
	Messages    []string `json:"messages"`
}

// Domain are the results of a domain.
type Domain struct {
	Name         string         `json:"name"`
	requirements []*Requirement `json:"requirements"`
}

// Report is the overall report.
type Report struct {
	Domains []*Domain `json:"domains"`
}
