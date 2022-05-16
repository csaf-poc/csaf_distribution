package main

import (
	"fmt"
	"strings"
	"testing"
)

const page0 = `<html>
<body>
	<a href="link0">link0</a>
	<ol>
		<li><a href="link1">link1</a></li>
		<li><a href="link2">link2</a></li>
	</ol>
	<p>
	<div>
		<li><a href="link3">link3</a></li>
	</div>
	<p>
</body>
</html>`

func TestLinksOnPage(t *testing.T) {

	links, err := linksOnPage(strings.NewReader(page0))
	if err != nil {
		t.Fatal(err)
	}

	if l := len(links); l != 4 {
		t.Fatalf("Expected 4 links, go %d\n", l)
	}

	for i, link := range links {
		href := fmt.Sprintf("link%d", i)
		if href != link {
			t.Fatalf("Expected link '%s', got '%s'\n", href, link)
		}
	}
}
