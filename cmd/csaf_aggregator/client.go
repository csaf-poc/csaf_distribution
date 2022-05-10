// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/time/rate"
)

type client interface {
	Do(req *http.Request) (*http.Response, error)
	Get(url string) (*http.Response, error)
	Head(url string) (*http.Response, error)
	Post(url, contentType string, body io.Reader) (*http.Response, error)
	PostForm(url string, data url.Values) (*http.Response, error)
}

type limitingClient struct {
	client
	limiter *rate.Limiter
}

func (lc *limitingClient) Do(req *http.Request) (*http.Response, error) {
	lc.limiter.Wait(context.Background())
	return lc.client.Do(req)
}

func (lc *limitingClient) Get(url string) (*http.Response, error) {
	lc.limiter.Wait(context.Background())
	return lc.client.Get(url)
}

func (lc *limitingClient) Head(url string) (*http.Response, error) {
	lc.limiter.Wait(context.Background())
	return lc.client.Head(url)
}

func (lc *limitingClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	lc.limiter.Wait(context.Background())
	return lc.client.Post(url, contentType, body)
}

func (lc *limitingClient) PostForm(url string, data url.Values) (*http.Response, error) {
	lc.limiter.Wait(context.Background())
	return lc.client.PostForm(url, data)
}

var errNotFound = errors.New("not found")

func downloadJSON(c client, url string, found func(io.Reader) error) error {
	res, err := c.Get(url)
	if err != nil || res.StatusCode != http.StatusOK ||
		res.Header.Get("Content-Type") != "application/json" {
		// ignore this as it is expected.
		return errNotFound
	}
	return func() error {
		defer res.Body.Close()
		return found(res.Body)
	}()
}
