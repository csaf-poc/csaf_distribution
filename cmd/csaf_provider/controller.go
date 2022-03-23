// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"embed"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strings"
)

//go:embed tmpl
var tmplFS embed.FS

type multiError []string

func (me multiError) Error() string {
	return strings.Join([]string(me), ", ")
}

func asMultiError(err error) multiError {
	if err == nil {
		return nil
	}
	e, ok := err.(multiError)
	if ok {
		return e
	}
	return multiError([]string{err.Error()})
}

// controller contains the config values and the html templates.
type controller struct {
	cfg  *config
	tmpl *template.Template
}

// newController assigns the given configs to a controller variable and parses the html template
// if the config value "NoWebUI" is true. It returns the controller variable and nil, otherwise error.
func newController(cfg *config) (*controller, error) {

	c := controller{cfg: cfg}
	var err error

	if !cfg.NoWebUI {
		if c.tmpl, err = template.ParseFS(tmplFS, "tmpl/*.html"); err != nil {
			return nil, err
		}
	}

	return &c, nil
}

// bind binds the paths with the corresponding http.handler and wraps it with the respective middleware,
// according to the "NoWebUI" config value.
func (c *controller) bind(pim *pathInfoMux) {
	if !c.cfg.NoWebUI {
		pim.handleFunc("/", c.auth(c.index))
		pim.handleFunc("/upload", c.auth(c.web(c.upload, "upload.html")))
		pim.handleFunc("/create", c.auth(c.web(c.create, "create.html")))
	}
	pim.handleFunc("/api/upload", c.auth(api(c.upload)))
	pim.handleFunc("/api/create", c.auth(api(c.create)))
}

// auth wraps the given http.HandlerFunc and returns an new one after authenticating the
// password contained in the header "X-CSAF-PROVIDER-AUTH" with the "password" config value
// if set, otherwise returns the given http.HandlerFunc.
func (c *controller) auth(
	fn func(http.ResponseWriter, *http.Request),
) func(http.ResponseWriter, *http.Request) {

	if c.cfg.Password == nil {
		return fn
	}
	return func(rw http.ResponseWriter, r *http.Request) {
		hash := r.Header.Get("X-CSAF-PROVIDER-AUTH")
		if !c.cfg.checkPassword(hash) {
			http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		fn(rw, r)
	}
}

// render sets the headers for the response. It applies the given template "tmpl" to
// the given object "arg" and writes the output to http.ResponseWriter.
// It logs a warning in case of error.
func (c *controller) render(rw http.ResponseWriter, tmpl string, arg interface{}) {
	rw.Header().Set("Content-type", "text/html; charset=utf-8")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	if err := c.tmpl.ExecuteTemplate(rw, tmpl, arg); err != nil {
		log.Printf("warn: %v\n", err)
	}
}

// failed constructs the error messages by calling "asMultiError" and calls "render"
// function to render the passed template and error object.
func (c *controller) failed(rw http.ResponseWriter, tmpl string, err error) {
	result := map[string]interface{}{"Error": asMultiError(err)}
	c.render(rw, tmpl, result)
}

// index calls the "render" function and passes the "index.html" and c.cfg to it.
func (c *controller) index(rw http.ResponseWriter, r *http.Request) {
	c.render(rw, "index.html", map[string]interface{}{
		"Config": c.cfg,
	})
}

// web executes the given function "fn", calls the "render" function and passes
// the result content from "fn", the given template and the http.ResponseWriter to it
// in case of no error occurred, otherwise calls the "failed" function and passes the given
// template and the error from "fn".
func (c *controller) web(
	fn func(*http.Request) (interface{}, error),
	tmpl string,
) func(http.ResponseWriter, *http.Request) {

	return func(rw http.ResponseWriter, r *http.Request) {
		if content, err := fn(r); err != nil {
			c.failed(rw, tmpl, err)
		} else {
			c.render(rw, tmpl, content)
		}
	}
}

// writeJSON sets the header for the response and writes the JSON encoding of the given "content".
// It logs out an error message in case of an error.
func writeJSON(rw http.ResponseWriter, content interface{}, code int) {
	rw.Header().Set("Content-type", "application/json; charset=utf-8")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.WriteHeader(code)
	if err := json.NewEncoder(rw).Encode(content); err != nil {
		log.Printf("error: %v\n", err)
	}
}

func errorToContent(err error) interface{} {
	return &struct {
		Errors multiError `json:"errors"`
	}{
		Errors: asMultiError(err),
	}
}

func api(
	fn func(*http.Request) (interface{}, error),
) func(http.ResponseWriter, *http.Request) {

	return func(rw http.ResponseWriter, r *http.Request) {
		if content, err := fn(r); err != nil {
			writeJSON(rw, errorToContent(err), http.StatusBadRequest)
		} else {
			writeJSON(rw, content, http.StatusOK)
		}
	}
}
