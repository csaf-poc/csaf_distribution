package main

type Requirement struct {
	Num         int
	Description string
	Messages    []string
}

type domain struct {
	Name         string
	Requirements []Requirement
}

type report struct {
	Domains []domain
}
