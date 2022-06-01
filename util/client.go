// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package util

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/time/rate"
)

// Client is an interface to abstract http.Client.
type Client interface {
	Do(req *http.Request) (*http.Response, error)
	Get(url string) (*http.Response, error)
	Head(url string) (*http.Response, error)
	Post(url, contentType string, body io.Reader) (*http.Response, error)
	PostForm(url string, data url.Values) (*http.Response, error)
}

// LoggingClient is a client that logs called URLs.
type LoggingClient struct {
	Client
}

// LimitingClient is a Client implementing rate throttling.
type LimitingClient struct {
	Client
	Limiter *rate.Limiter
}

// Do implements the respective method of the Client interface.
func (lc *LoggingClient) Do(req *http.Request) (*http.Response, error) {
	log.Printf("[DO]: %s\n", req.URL.String())
	return lc.Do(req)
}

// Get implements the respective method of the Client interface.
func (lc *LoggingClient) Get(url string) (*http.Response, error) {
	log.Printf("[GET]: %s\n", url)
	return lc.Client.Get(url)
}

// Head implements the respective method of the Client interface.
func (lc *LoggingClient) Head(url string) (*http.Response, error) {
	log.Printf("[HEAD]: %s\n", url)
	return lc.Head(url)
}

// Post implements the respective method of the Client interface.
func (lc *LoggingClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	log.Printf("[POST]: %s\n", url)
	return lc.Post(url, contentType, body)
}

// PostForm implements the respective method of the Client interface.
func (lc *LoggingClient) PostForm(url string, data url.Values) (*http.Response, error) {
	log.Printf("[POST FORM]: %s\n", url)
	return lc.PostForm(url, data)
}

// Do implements the respective method of the Client interface.
func (lc *LimitingClient) Do(req *http.Request) (*http.Response, error) {
	lc.Limiter.Wait(context.Background())
	return lc.Client.Do(req)
}

// Get implements the respective method of the Client interface.
func (lc *LimitingClient) Get(url string) (*http.Response, error) {
	lc.Limiter.Wait(context.Background())
	return lc.Client.Get(url)
}

// Head implements the respective method of the Client interface.
func (lc *LimitingClient) Head(url string) (*http.Response, error) {
	lc.Limiter.Wait(context.Background())
	return lc.Client.Head(url)
}

// Post implements the respective method of the Client interface.
func (lc *LimitingClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	lc.Limiter.Wait(context.Background())
	return lc.Client.Post(url, contentType, body)
}

// PostForm implements the respective method of the Client interface.
func (lc *LimitingClient) PostForm(url string, data url.Values) (*http.Response, error) {
	lc.Limiter.Wait(context.Background())
	return lc.Client.PostForm(url, data)
}
