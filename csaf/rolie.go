package csaf

type Link struct {
	Rel  string `json:"rel"`
	HRef string `json:"href"`
}

type Category struct {
	Scheme string `json:"scheme"`
	Term   string `json:"term"`
}

type Summary struct {
	Content string `json:"content"`
}

type Content struct {
	Type string `json:"type"`
	Src  string `json:"src"`
}

type Format struct {
	Schema  string `json:"schema"`
	Version string `json:"version"`
}

type Entry struct {
	ID        string    `json:"id"`
	Titel     string    `json:"title"`
	Link      []Link    `json:"link"`
	Published TimeStamp `json:"published"`
	Updated   TimeStamp `json:"updated"`
	Summary   Summary   `json:"summary"`
	Content   Content   `json:"content"`
	Format    Format    `json:"format"`
}

type ROLIEFeed struct {
	ID       string     `json:"id"`
	Title    string     `json:"title"`
	Link     []Link     `json:"link"`
	Category []Category `json:"category"`
	Updated  TimeStamp  `json:"updated"`
	Entry    []*Entry   `json:"entry"`
}
