package main

import (
	"embed"
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

type controller struct {
	cfg  *config
	tmpl *template.Template
}

func newController(cfg *config) (*controller, error) {

	c := controller{cfg: cfg}
	var err error

	if c.tmpl, err = template.ParseFS(tmplFS, "tmpl/*.html"); err != nil {
		return nil, err
	}

	return &c, nil
}

func (c *controller) bind(pim *pathInfoMux) {
	pim.handleFunc("/", c.index)
	pim.handleFunc("/upload", c.uploadWeb)
	pim.handleFunc("/create", c.createWeb)
}

func (c *controller) render(rw http.ResponseWriter, tmpl string, arg interface{}) {
	rw.Header().Set("Content-type", "text/html; charset=utf-8")
	if err := c.tmpl.ExecuteTemplate(rw, tmpl, arg); err != nil {
		log.Printf("warn: %v\n", err)
	}
}

func (c *controller) failed(rw http.ResponseWriter, tmpl string, err error) {
	if _, ok := err.(multiError); err != nil && !ok {
		err = multiError([]string{err.Error()})
	}
	result := map[string]interface{}{"Error": err}
	c.render(rw, tmpl, result)
}

func (c *controller) index(rw http.ResponseWriter, r *http.Request) {
	c.render(rw, "index.html", map[string]interface{}{
		"Config": c.cfg,
	})
}

func (c *controller) createWeb(rw http.ResponseWriter, r *http.Request) {
	if err := c.create(rw, r); err != nil {
		c.failed(rw, "create.html", err)
		return
	}
	c.render(rw, "create.html", nil)
}

func (c *controller) uploadWeb(rw http.ResponseWriter, r *http.Request) {
	result, err := c.upload(rw, r)
	if err != nil {
		c.failed(rw, "upload.html", err)
		return
	}
	c.render(rw, "upload.html", result)
}
