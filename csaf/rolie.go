package csaf

import (
	"encoding/json"
	"io"
	"sort"
	"time"
)

// Link for ROLIE.
type Link struct {
	Rel  string `json:"rel"`
	HRef string `json:"href"`
}

// ROLIECategory for ROLIE.
type ROLIECategory struct {
	Scheme string `json:"scheme"`
	Term   string `json:"term"`
}

// Summary for ROLIE.
type Summary struct {
	Content string `json:"content"`
}

// Content for ROLIE.
type Content struct {
	Type string `json:"type"`
	Src  string `json:"src"`
}

// Format for ROLIE.
type Format struct {
	Schema  string `json:"schema"`
	Version string `json:"version"`
}

// Entry for ROLIE.
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

// ROLIEFeed is a ROLIE feed.
type ROLIEFeed struct {
	ID       string          `json:"id"`
	Title    string          `json:"title"`
	Link     []Link          `json:"link,omitempty"`
	Category []ROLIECategory `json:"category,omitempty"`
	Updated  TimeStamp       `json:"updated"`
	Entry    []*Entry        `json:"entry,omitempty"`
}

// LoadROLIEFeed loads a ROLIE feed from a reader.
func LoadROLIEFeed(r io.Reader) (*ROLIEFeed, error) {
	dec := json.NewDecoder(r)
	var rf ROLIEFeed
	if err := dec.Decode(&rf); err != nil {
		return nil, err
	}
	return &rf, nil
}

// WriteTo saves a ROLIE feed to a writer.
func (rf *ROLIEFeed) WriteTo(w io.Writer) (int64, error) {
	nw := nWriter{w, 0}
	enc := json.NewEncoder(&nw)
	enc.SetIndent("", "  ")
	err := enc.Encode(rf)
	return nw.n, err
}

// EntryByID looks up an entry by its ID.
// Returns nil if no such entry was found.
func (rf *ROLIEFeed) EntryByID(id string) *Entry {
	for _, entry := range rf.Entry {
		if entry.ID == id {
			return entry
		}
	}
	return nil
}

// SortEntriesByUpdated sorts all the entries in the feed
// by their update times.
func (rf *ROLIEFeed) SortEntriesByUpdated() {
	entries := rf.Entry
	sort.Slice(entries, func(i, j int) bool {
		return time.Time(entries[j].Updated).Before(time.Time(entries[i].Updated))
	})
}
