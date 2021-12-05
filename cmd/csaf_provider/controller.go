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

type controller struct {
	cfg  *config
	tmpl *template.Template
}

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

func (c *controller) bind(pim *pathInfoMux) {
	if !c.cfg.NoWebUI {
		pim.handleFunc("/", c.index)
		pim.handleFunc("/upload", c.web(c.upload, "upload.html"))
		pim.handleFunc("/create", c.web(c.create, "create.html"))
	}
	pim.handleFunc("/api/upload", api(c.upload))
	pim.handleFunc("/api/create", api(c.create))
}

func (c *controller) render(rw http.ResponseWriter, tmpl string, arg interface{}) {
	rw.Header().Set("Content-type", "text/html; charset=utf-8")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	if err := c.tmpl.ExecuteTemplate(rw, tmpl, arg); err != nil {
		log.Printf("warn: %v\n", err)
	}
}

func (c *controller) failed(rw http.ResponseWriter, tmpl string, err error) {
	result := map[string]interface{}{"Error": asMultiError(err)}
	c.render(rw, tmpl, result)
}

func (c *controller) index(rw http.ResponseWriter, r *http.Request) {
	c.render(rw, "index.html", map[string]interface{}{
		"Config": c.cfg,
	})
}

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
