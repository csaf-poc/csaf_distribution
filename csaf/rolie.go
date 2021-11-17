package csaf

import (
	"encoding/json"
	"io"
	"sort"
	"time"
)

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
	Summary   *Summary  `json:"summary,omitempty"`
	Content   Content   `json:"content"`
	Format    Format    `json:"format"`
}

type ROLIEFeed struct {
	ID       string     `json:"id"`
	Title    string     `json:"title"`
	Link     []Link     `json:"link,omitempty"`
	Category []Category `json:"category,omitempty"`
	Updated  TimeStamp  `json:"updated"`
	Entry    []*Entry   `json:"entry,omitempty"`
}

func LoadROLIEFeed(r io.Reader) (*ROLIEFeed, error) {
	dec := json.NewDecoder(r)
	var rf ROLIEFeed
	if err := dec.Decode(&rf); err != nil {
		return nil, err
	}
	return &rf, nil
}

func (rf *ROLIEFeed) Save(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rf)
}

func (rf *ROLIEFeed) EntryByID(id string) *Entry {
	for _, entry := range rf.Entry {
		if entry.ID == id {
			return entry
		}
	}
	return nil
}

func (rf *ROLIEFeed) SortEntriesByUpdated() {
	entries := rf.Entry
	sort.Slice(entries, func(i, j int) bool {
		return time.Time(entries[j].Updated).Before(time.Time(entries[i].Updated))
	})
}
