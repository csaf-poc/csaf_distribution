package main

import (
	"net/http"
	"os"
	"strings"
)

type pathInfoMux struct {
	routes map[string]http.Handler
}

func newPathInfoMux() *pathInfoMux {
	return &pathInfoMux{routes: map[string]http.Handler{}}
}

func (pim *pathInfoMux) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	pi := os.Getenv("PATH_INFO")
	if h, ok := pim.routes[pi]; ok {
		h.ServeHTTP(rw, req)
		return
	}
	for k, v := range pim.routes {
		if strings.HasPrefix(k, pi) {
			v.ServeHTTP(rw, req)
			return
		}
	}
	http.NotFound(rw, req)
}

func (pim *pathInfoMux) handle(pattern string, handler http.Handler) {
	pim.routes[pattern] = handler
}

func (pim *pathInfoMux) handleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	pim.handle(pattern, http.HandlerFunc(handler))
}
