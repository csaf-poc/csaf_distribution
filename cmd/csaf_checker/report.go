// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"time"

	"github.com/csaf-poc/csaf_distribution/v2/csaf"
)

// MessageType is the kind of the message.
type MessageType int

const (
	// InfoType represents an info message.
	InfoType MessageType = iota
	// WarnType represents a warning message.
	WarnType
	// ErrorType represents an error message.
	ErrorType
)

// Message is a typed text message.
type Message struct {
	Type MessageType `json:"type"`
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
	Name         string             `json:"name"`
	Publisher    *csaf.Publisher    `json:"publisher,omitempty"`
	Role         *csaf.MetadataRole `json:"role,omitempty"`
	Requirements []*Requirement     `json:"requirements,omitempty"`
	Passed       bool               `json:"passed"`
}

// ReportTime stores the time of the report.
type ReportTime struct{ time.Time }

// Report is the overall report.
type Report struct {
	Domains []*Domain  `json:"domains,omitempty"`
	Version string     `json:"version,omitempty"`
	Date    ReportTime `json:"date,omitempty"`
}

// MarshalText implements the encoding.TextMarshaller interface.
func (rt ReportTime) MarshalText() ([]byte, error) {
	return []byte(rt.Format(time.RFC3339)), nil
}

// HasErrors tells if this requirement has errors.
func (r *Requirement) HasErrors() bool {
	for i := range r.Messages {
		if r.Messages[i].Type == ErrorType {
			return true
		}
	}
	return false
}

// Append appends messages to requirement.
func (r *Requirement) Append(msgs []Message) {
	r.Messages = append(r.Messages, msgs...)
}

// HasErrors tells if this domain has errors.
func (d *Domain) HasErrors() bool {
	return !d.Passed
}

// String implements fmt.Stringer interface.
func (mt MessageType) String() string {
	switch mt {
	case InfoType:
		return "INFO"
	case WarnType:
		return "WARN"
	case ErrorType:
		return "ERROR"
	default:
		return fmt.Sprintf("MessageType (%d)", int(mt))
	}
}

// message appends typed messages to a requirement.
func (r *Requirement) message(typ MessageType, texts ...string) {
	for _, text := range texts {
		r.Messages = append(r.Messages, Message{Type: typ, Text: text})
	}
}
