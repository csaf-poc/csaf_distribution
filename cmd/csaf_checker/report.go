package main

type requirement struct {
	Num         int      `json:"num"`
	Description string   `json:"description"`
	Messages    []string `json:"messages"`
}

type domain struct {
	Name         string        `json:"name"`
	requirements []requirement `json:"requirements"`
}

type report struct {
	Domains []domain `json:"domains"`
}
