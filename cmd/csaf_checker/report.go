// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

// MessageKind ist the kind of the message.
type MessageKind int

const (
	InfoKind MessageKind = iota
	WarnKind
	ErrorKind
)

// Message is a tagged text message.
type Message struct {
	Kind MessageKind `json:"kind"`
	Text string      `json:"text"`
}

// Requirement a single requirement report of a domain.
type Requirement struct {
	Num         int       `json:"num"`
	Description string    `json:"description"`
	Messages    []Message `json:"messages,omitempty"`
}

// Domain are the results of a domain.
type Domain struct {
	Name         string         `json:"name"`
	Requirements []*Requirement `json:"requirements,omitempty"`
}

// Report is the overall report.
type Report struct {
	Domains []*Domain `json:"domains,omitempty"`
	Version string    `json:"version,omitempty"`
	Date    string    `json:"date,omitempty"`
}

// HasErrors tells if this requirement has errors.
func (r *Requirement) HasErrors() bool {
	for _, m := range r.Messages {
		if m.Kind == ErrorKind {
			return true
		}
	}
	return false
}

func (r *Requirement) message(kind MessageKind, texts ...string) {
	for _, text := range texts {
		r.Messages = append(r.Messages, Message{Kind: kind, Text: text})
	}
}
