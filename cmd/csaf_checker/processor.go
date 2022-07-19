// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"golang.org/x/time/rate"

	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

// topicMessages stores the collected topicMessages for a specific topic.
type topicMessages []Message

type processor struct {
	opts      *options
	client    util.Client
	ageAccept func(time.Time) bool

	redirects      map[string][]string
	noneTLS        map[string]struct{}
	alreadyChecked map[string]whereType
	pmdURL         string
	pmd256         []byte
	pmd            interface{}
	keys           []*crypto.KeyRing

	badIntegrities       topicMessages
	badPGPs              topicMessages
	badSignatures        topicMessages
	badProviderMetadata  topicMessages
	badSecurity          topicMessages
	badIndices           topicMessages
	badChanges           topicMessages
	badFolders           topicMessages
	badWellknownMetadata topicMessages
	badDNSPath           topicMessages
	badDirListings       topicMessages

	expr *util.PathEval
}

// reporter is implemented by any value that has a report method.
// The implementation of the report controls how to test
// the respective requirement and generate the report.
type reporter interface {
	report(*processor, *Domain)
}

var (
	// errContinue indicates that the current check should continue.
	errContinue = errors.New("continue")
	// errStop indicates that the current check should stop.
	errStop = errors.New("stop")
)

type whereType byte

const (
	rolieMask = whereType(1) << iota
	rolieIndexMask
	rolieChangesMask
	indexMask
	changesMask
	listingMask
	rolieListingMask
)

func (wt whereType) String() string {
	switch wt {
	case rolieMask:
		return "ROLIE"
	case rolieIndexMask:
		return "index.txt [ROLIE]"
	case rolieChangesMask:
		return "changes.csv [ROLIE]"
	case indexMask:
		return "index.txt"
	case changesMask:
		return "changes.csv"
	case listingMask:
		return "directory listing"
	case rolieListingMask:
		return "directory listing [ROLIE]"
	default:
		var mixed []string
		for mask := rolieMask; mask <= changesMask; mask <<= 1 {
			if x := wt & mask; x == mask {
				mixed = append(mixed, x.String())
			}
		}
		return strings.Join(mixed, "|")
	}
}

// add adds a message to this topic.
func (m *topicMessages) add(typ MessageType, format string, args ...interface{}) {
	*m = append(*m, Message{Type: typ, Text: fmt.Sprintf(format, args...)})
}

// error adds an error message to this topic.
func (m *topicMessages) error(format string, args ...interface{}) {
	m.add(ErrorType, format, args...)
}

// warn adds a warning message to this topic.
func (m *topicMessages) warn(format string, args ...interface{}) {
	m.add(WarnType, format, args...)
}

// info adds an info message to this topic.
func (m *topicMessages) info(format string, args ...interface{}) {
	m.add(InfoType, format, args...)
}

// use signals that we going to use this topic.
func (m *topicMessages) use() {
	if *m == nil {
		*m = []Message{}
	}
}

// reset resets the messages to this topic.
func (m *topicMessages) reset() { *m = nil }

// used returns true if we have used this topic.
func (m *topicMessages) used() bool { return *m != nil }

// newProcessor returns a processor structure after assigning the given options to the opts attribute
// and initializing the "alreadyChecked" and "expr" fields.
func newProcessor(opts *options) *processor {
	return &processor{
		opts:           opts,
		alreadyChecked: map[string]whereType{},
		expr:           util.NewPathEval(),
		ageAccept:      ageAccept(opts),
	}
}

func ageAccept(opts *options) func(time.Time) bool {
	if opts.Years == nil {
		return nil
	}
	good := time.Now().AddDate(-int(*opts.Years), 0, 0)
	return func(t time.Time) bool {
		return !t.Before(good)
	}
}

// clean clears the fields values of the given processor.
func (p *processor) clean() {
	p.redirects = nil
	p.noneTLS = nil
	for k := range p.alreadyChecked {
		delete(p.alreadyChecked, k)
	}
	p.pmdURL = ""
	p.pmd256 = nil
	p.pmd = nil
	p.keys = nil

	p.badIntegrities.reset()
	p.badPGPs.reset()
	p.badSignatures.reset()
	p.badProviderMetadata.reset()
	p.badSecurity.reset()
	p.badIndices.reset()
	p.badChanges.reset()
	p.badFolders.reset()
	p.badWellknownMetadata.reset()
	p.badDNSPath.reset()
	p.badDirListings.reset()
}

// run calls checkDomain function for each domain in the given "domains" parameter.
// Then it calls the report method on each report from the given "reporters" parameter for each domain.
// It returns a pointer to the report and nil, otherwise an error.
func (p *processor) run(reporters []reporter, domains []string) (*Report, error) {

	report := Report{
		Date:    ReportTime{Time: time.Now().UTC()},
		Version: util.SemVersion,
	}

	for _, d := range domains {
		if err := p.checkDomain(d); err != nil {
			if err == errContinue || err == errStop {
				continue
			}
			return nil, err
		}
		domain := &Domain{Name: d}
		for _, r := range reporters {
			r.report(p, domain)
		}
		report.Domains = append(report.Domains, domain)
		p.clean()
	}

	return &report, nil
}

// domainChecks compiles a list of checks which should be performed
// for a given domain.
func (p *processor) domainChecks(domain string) []func(*processor, string) error {

	// If we have a direct domain url we dont need to
	// perform certain checks.
	direct := strings.HasPrefix(domain, "https://")

	checks := []func(*processor, string) error{
		(*processor).checkProviderMetadata,
		(*processor).checkPGPKeys,
	}

	if !direct {
		checks = append(checks, (*processor).checkSecurity)
	}

	checks = append(checks,
		(*processor).checkCSAFs,
		(*processor).checkMissing,
		(*processor).checkInvalid,
		(*processor).checkListing,
	)

	if !direct {
		checks = append(checks,
			(*processor).checkWellknownMetadataReporter,
			(*processor).checkDNSPathReporter,
		)
	}

	return checks
}

func (p *processor) checkDomain(domain string) error {

	for _, check := range p.domainChecks(domain) {
		if err := check(p, domain); err != nil && err != errContinue {
			if err == errStop {
				return nil
			}
			return err
		}
	}

	return nil
}

// checkTLS parses the given URL to check its schema, as a result it sets
// the value of "noneTLS" field if it is not HTTPS.
func (p *processor) checkTLS(u string) {
	if p.noneTLS == nil {
		p.noneTLS = map[string]struct{}{}
	}
	if x, err := url.Parse(u); err == nil && x.Scheme != "https" {
		p.noneTLS[u] = struct{}{}
	}
}

func (p *processor) markChecked(s string, mask whereType) bool {
	v, ok := p.alreadyChecked[s]
	p.alreadyChecked[s] = v | mask
	return ok
}

func (p *processor) checkRedirect(r *http.Request, via []*http.Request) error {

	url := r.URL.String()
	p.checkTLS(url)
	if p.redirects == nil {
		p.redirects = map[string][]string{}
	}

	if redirects := p.redirects[url]; len(redirects) == 0 {
		redirects = make([]string, len(via))
		for i, v := range via {
			redirects[i] = v.URL.String()
		}
		p.redirects[url] = redirects
	}

	if len(via) > 10 {
		return errors.New("too many redirections")
	}
	return nil
}

func (p *processor) httpClient() util.Client {

	if p.client != nil {
		return p.client
	}

	hClient := http.Client{}

	hClient.CheckRedirect = p.checkRedirect

	var tlsConfig tls.Config
	if p.opts.Insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	if p.opts.ClientCert != nil && p.opts.ClientKey != nil {
		cert, err := tls.LoadX509KeyPair(*p.opts.ClientCert, *p.opts.ClientKey)
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	hClient.Transport = &http.Transport{
		TLSClientConfig: &tlsConfig,
	}

	var client util.Client

	if p.opts.Verbose {
		client = &util.LoggingClient{Client: &hClient}
	} else {
		client = &hClient
	}

	if p.opts.Rate == nil {
		p.client = client
		return client
	}

	p.client = &util.LimitingClient{
		Client:  client,
		Limiter: rate.NewLimiter(rate.Limit(*p.opts.Rate), 1),
	}

	return p.client
}

var yearFromURL = regexp.MustCompile(`.*/(\d{4})/[^/]+$`)

func (p *processor) integrity(
	files []csaf.AdvisoryFile,
	base string,
	mask whereType,
	lg func(MessageType, string, ...interface{}),
) error {
	b, err := url.Parse(base)
	if err != nil {
		return err
	}
	client := p.httpClient()

	var data bytes.Buffer

	for _, f := range files {
		fp, err := url.Parse(f.URL())
		if err != nil {
			lg(ErrorType, "Bad URL %s: %v", f, err)
			continue
		}
		u := b.ResolveReference(fp).String()
		if p.markChecked(u, mask) {
			continue
		}
		p.checkTLS(u)

		var folderYear *int

		if m := yearFromURL.FindStringSubmatch(u); m != nil {
			year, _ := strconv.Atoi(m[1])
			// Check if we are in checking time interval.
			if p.ageAccept != nil && !p.ageAccept(
				time.Date(
					year, 12, 31, // Assume last day og year.
					23, 59, 59, 0, // 23:59:59
					time.UTC)) {
				continue
			}
			folderYear = &year
		}

		res, err := client.Get(u)
		if err != nil {
			lg(ErrorType, "Fetching %s failed: %v.", u, err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			lg(ErrorType, "Fetching %s failed: Status code %d (%s)",
				u, res.StatusCode, res.Status)
			continue
		}

		s256 := sha256.New()
		s512 := sha512.New()
		data.Reset()
		hasher := io.MultiWriter(s256, s512, &data)

		var doc interface{}

		if err := func() error {
			defer res.Body.Close()
			tee := io.TeeReader(res.Body, hasher)
			return json.NewDecoder(tee).Decode(&doc)
		}(); err != nil {
			lg(ErrorType, "Reading %s failed: %v", u, err)
			continue
		}

		errors, err := csaf.ValidateCSAF(doc)
		if err != nil {
			lg(ErrorType, "Failed to validate %s: %v", u, err)
			continue
		}
		if len(errors) > 0 {
			lg(ErrorType, "CSAF file %s has %d validation errors.", u, len(errors))
		}

		// Check if file is in the right folder.
		p.badFolders.use()

		if date, err := p.expr.Eval(
			`$.document.tracking.initial_release_date`, doc); err != nil {
			p.badFolders.error(
				"Extracting 'initial_release_date' from %s failed: %v", u, err)
		} else if text, ok := date.(string); !ok {
			p.badFolders.error("'initial_release_date' is not a string in %s", u)
		} else if d, err := time.Parse(time.RFC3339, text); err != nil {
			p.badFolders.error(
				"Parsing 'initial_release_date' as RFC3339 failed in %s: %v", u, err)
		} else if folderYear == nil {
			p.badFolders.error("No year folder found in %s", u)
		} else if d.UTC().Year() != *folderYear {
			p.badFolders.error("%s should be in folder %d", u, d.UTC().Year())
		}

		// Check hashes
		p.badIntegrities.use()

		for _, x := range []struct {
			ext  string
			url  func() string
			hash []byte
		}{
			{"SHA256", f.SHA256URL, s256.Sum(nil)},
			{"SHA512", f.SHA512URL, s512.Sum(nil)},
		} {
			hu, err := url.Parse(x.url())
			if err != nil {
				lg(ErrorType, "Bad URL %s: %v", x.url(), err)
				continue
			}
			hashFile := b.ResolveReference(hu).String()
			p.checkTLS(hashFile)
			if res, err = client.Get(hashFile); err != nil {
				p.badIntegrities.error("Fetching %s failed: %v.", hashFile, err)
				continue
			}
			if res.StatusCode != http.StatusOK {
				p.badIntegrities.error("Fetching %s failed: Status code %d (%s)",
					hashFile, res.StatusCode, res.Status)
				continue
			}
			h, err := func() ([]byte, error) {
				defer res.Body.Close()
				return util.HashFromReader(res.Body)
			}()
			if err != nil {
				p.badIntegrities.error("Reading %s failed: %v.", hashFile, err)
				continue
			}
			if len(h) == 0 {
				p.badIntegrities.error("No hash found in %s.", hashFile)
				continue
			}
			if !bytes.Equal(h, x.hash) {
				p.badIntegrities.error("%s hash of %s does not match %s.",
					x.ext, u, hashFile)
			}
		}

		// Check signature
		su, err := url.Parse(f.SignURL())
		if err != nil {
			lg(ErrorType, "Bad URL %s: %v", f.SignURL(), err)
			continue
		}
		sigFile := b.ResolveReference(su).String()
		p.checkTLS(sigFile)

		p.badSignatures.use()

		if res, err = client.Get(sigFile); err != nil {
			p.badSignatures.error("Fetching %s failed: %v.", sigFile, err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			p.badSignatures.error("Fetching %s failed: status code %d (%s)",
				sigFile, res.StatusCode, res.Status)
			continue
		}

		sig, err := func() (*crypto.PGPSignature, error) {
			defer res.Body.Close()
			all, err := io.ReadAll(res.Body)
			if err != nil {
				return nil, err
			}
			return crypto.NewPGPSignatureFromArmored(string(all))
		}()
		if err != nil {
			p.badSignatures.error("Loading signature from %s failed: %v.",
				sigFile, err)
			continue
		}

		if len(p.keys) > 0 {
			pm := crypto.NewPlainMessage(data.Bytes())
			t := crypto.GetUnixTime()
			var verified bool
			for _, key := range p.keys {
				if err := key.VerifyDetached(pm, sig, t); err == nil {
					verified = true
					break
				}
			}
			if !verified {
				p.badSignatures.error("Signature of %s could not be verified.", u)
			}
		}
	}
	return nil
}

func (p *processor) processROLIEFeed(feed string) error {
	client := p.httpClient()
	res, err := client.Get(feed)
	if err != nil {
		p.badProviderMetadata.error("Cannot fetch feed %s: %v", feed, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		p.badProviderMetadata.warn("Fetching %s failed. Status code %d (%s)",
			feed, res.StatusCode, res.Status)
		return errContinue
	}

	rfeed, rolieDoc, err := func() (*csaf.ROLIEFeed, interface{}, error) {
		defer res.Body.Close()
		all, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, nil, err
		}
		rfeed, err := csaf.LoadROLIEFeed(bytes.NewReader(all))
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %v", feed, err)
		}
		var rolieDoc interface{}
		err = json.NewDecoder(bytes.NewReader(all)).Decode(&rolieDoc)
		return rfeed, rolieDoc, err

	}()
	if err != nil {
		p.badProviderMetadata.error("Loading ROLIE feed failed: %v.", err)
		return errContinue
	}
	errors, err := csaf.ValidateROLIE(rolieDoc)
	if err != nil {
		return err
	}
	if len(errors) > 0 {
		p.badProviderMetadata.error("%s: Validating against JSON schema failed:", feed)
		for _, msg := range errors {
			p.badProviderMetadata.error(strings.ReplaceAll(msg, `%`, `%%`))
		}
	}

	feedURL, err := url.Parse(feed)
	if err != nil {
		p.badProviderMetadata.error("Bad base path: %v", err)
		return errContinue
	}

	base, err := util.BaseURL(feedURL)
	if err != nil {
		p.badProviderMetadata.error("Bad base path: %v", err)
		return errContinue
	}

	// Extract the CSAF files from feed.
	var files []csaf.AdvisoryFile

	rfeed.Entries(func(entry *csaf.Entry) {

		// Filter if we have date checking.
		if p.ageAccept != nil {
			if pub := time.Time(entry.Published); !pub.IsZero() && !p.ageAccept(pub) {
				return
			}
		}

		var url, sha256, sha512, sign string

		for i := range entry.Link {
			link := &entry.Link[i]
			lower := strings.ToLower(link.HRef)
			switch link.Rel {
			case "self":
				if !strings.HasSuffix(lower, ".json") {
					p.badProviderMetadata.warn(
						`ROLIE feed entry link %s in %s with "rel": "self" has unexpected file extension.`,
						link.HRef, feed)
				}
				url = link.HRef
			case "signature":
				if !strings.HasSuffix(lower, ".asc") {
					p.badProviderMetadata.warn(
						`ROLIE feed entry link %s in %s with "rel": "signature" has unexpected file extension.`,
						link.HRef, feed)
				}
				sign = link.HRef
			case "hash":
				switch {
				case strings.HasSuffix(lower, "sha256"):
					sha256 = link.HRef
				case strings.HasSuffix(lower, "sha512"):
					sha512 = link.HRef
				default:
					p.badProviderMetadata.warn(
						`ROLIE feed entry link %s in %s with "rel": "hash" has unsupported file extension.`,
						link.HRef, feed)
				}
			}
		}

		if url == "" {
			p.badProviderMetadata.warn(
				`ROLIE feed %s contains entry link with no "self" URL.`, feed)
			return
		}

		var file csaf.AdvisoryFile

		if sha256 != "" || sha512 != "" || sign != "" {
			file = csaf.HashedAdvisoryFile{url, sha256, sha512, sign}
		} else {
			file = csaf.PlainAdvisoryFile(url)
		}

		files = append(files, file)
	})

	if err := p.integrity(files, base, rolieMask, p.badProviderMetadata.add); err != nil &&
		err != errContinue {
		return err
	}

	if err := p.checkIndex(base, rolieIndexMask); err != nil && err != errContinue {
		return err
	}

	if err := p.checkChanges(base, rolieChangesMask); err != nil && err != errContinue {
		return err
	}

	return nil
}

// checkIndex fetches the "index.txt" and calls "checkTLS" method for HTTPS checks.
// It extracts the file names from the file and passes them to "integrity" function.
// It returns error if fetching/reading the file(s) fails, otherwise nil.
func (p *processor) checkIndex(base string, mask whereType) error {
	client := p.httpClient()

	bu, err := url.Parse(base)
	if err != nil {
		return err
	}

	index := util.JoinURLPath(bu, "index.txt").String()

	p.checkTLS(index)

	p.badIndices.use()

	res, err := client.Get(index)
	if err != nil {
		p.badIndices.error("Fetching %s failed: %v", index, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		// It's optional
		if res.StatusCode != http.StatusNotFound {
			p.badIndices.error("Fetching %s failed. Status code %d (%s)",
				index, res.StatusCode, res.Status)
		}
		return errContinue
	}

	files, err := func() ([]csaf.AdvisoryFile, error) {
		defer res.Body.Close()
		var files []csaf.AdvisoryFile
		scanner := bufio.NewScanner(res.Body)
		for scanner.Scan() {
			files = append(files, csaf.PlainAdvisoryFile(scanner.Text()))
		}
		return files, scanner.Err()
	}()
	if err != nil {
		p.badIndices.error("Reading %s failed: %v", index, err)
		return errContinue
	}

	return p.integrity(files, base, mask, p.badIndices.add)
}

// checkChanges fetches the "changes.csv" and calls the "checkTLS" method for HTTPs checks.
// It extracts the file content, tests the column number and the validity of the time format
// of the fields' values and if they are sorted properly. Then it passes the files to the
// "integrity" functions. It returns error if some test fails, otherwise nil.
func (p *processor) checkChanges(base string, mask whereType) error {

	bu, err := url.Parse(base)
	if err != nil {
		return err
	}
	changes := util.JoinURLPath(bu, "changes.csv").String()

	p.checkTLS(changes)

	client := p.httpClient()
	res, err := client.Get(changes)

	p.badChanges.use()

	if err != nil {
		p.badChanges.error("Fetching %s failed: %v", changes, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		if res.StatusCode != http.StatusNotFound {
			// It's optional
			p.badChanges.error("Fetching %s failed. Status code %d (%s)",
				changes, res.StatusCode, res.Status)
		}
		return errContinue
	}

	times, files, err := func() ([]time.Time, []csaf.AdvisoryFile, error) {
		defer res.Body.Close()
		var times []time.Time
		var files []csaf.AdvisoryFile
		c := csv.NewReader(res.Body)
		const (
			pathColumn = 0
			timeColumn = 1
		)
		for {
			r, err := c.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, nil, err
			}
			if len(r) < 2 {
				return nil, nil, errors.New("not enough columns")
			}
			t, err := time.Parse(time.RFC3339, r[timeColumn])
			if err != nil {
				return nil, nil, err
			}
			// Apply date range filtering.
			if p.ageAccept != nil && !p.ageAccept(t) {
				continue
			}
			times, files =
				append(times, t),
				append(files, csaf.PlainAdvisoryFile(r[pathColumn]))
		}
		return times, files, nil
	}()
	if err != nil {
		p.badChanges.error("Reading %s failed: %v", changes, err)
		return errContinue
	}

	if !sort.SliceIsSorted(times, func(i, j int) bool {
		return times[j].Before(times[i])
	}) {
		p.badChanges.error("%s is not sorted in descending order", changes)
	}

	return p.integrity(files, base, mask, p.badChanges.add)
}

func (p *processor) processROLIEFeeds(domain string, feeds [][]csaf.Feed) error {

	base, err := url.Parse(p.pmdURL)
	if err != nil {
		return err
	}
	for _, fs := range feeds {
		for i := range fs {
			feed := &fs[i]
			if feed.URL == nil {
				continue
			}
			up, err := url.Parse(string(*feed.URL))
			if err != nil {
				p.badProviderMetadata.error("Invalid URL %s in feed: %v.", *feed.URL, err)
				continue
			}
			feedURL := base.ResolveReference(up).String()
			p.checkTLS(feedURL)
			if err := p.processROLIEFeed(feedURL); err != nil && err != errContinue {
				return err
			}
		}
	}
	return nil
}

func (p *processor) checkCSAFs(domain string) error {
	// Check for ROLIE
	rolie, err := p.expr.Eval("$.distributions[*].rolie.feeds", p.pmd)
	if err != nil {
		return err
	}

	fs, hasRolie := rolie.([]interface{})
	hasRolie = hasRolie && len(fs) > 0

	if hasRolie {
		var feeds [][]csaf.Feed
		if err := util.ReMarshalJSON(&feeds, rolie); err != nil {
			p.badProviderMetadata.error("ROLIE feeds are not compatible: %v.", err)
		} else if err := p.processROLIEFeeds(domain, feeds); err != nil {
			if err != errContinue {
				return err
			}
		}
	}

	// No rolie feeds
	pmdURL, err := url.Parse(p.pmdURL)
	if err != nil {
		return err
	}
	base, err := util.BaseURL(pmdURL)
	if err != nil {
		return err
	}

	if err := p.checkIndex(base, indexMask); err != nil && err != errContinue {
		return err
	}

	if err := p.checkChanges(base, changesMask); err != nil && err != errContinue {
		return err
	}

	return nil
}

func (p *processor) checkMissing(string) error {
	var maxMask whereType

	for _, v := range p.alreadyChecked {
		maxMask |= v
	}

	var files []string

	for f, v := range p.alreadyChecked {
		if v != maxMask {
			files = append(files, f)
		}
	}
	sort.Strings(files)
	for _, f := range files {
		v := p.alreadyChecked[f]
		var where []string
		for mask := rolieMask; mask <= rolieListingMask; mask <<= 1 {
			if maxMask&mask == mask {
				var in string
				if v&mask == mask {
					in = "in"
				} else {
					in = "not in"
				}
				where = append(where, in+" "+mask.String())
			}
		}
		p.badIntegrities.error("%s %s", f, strings.Join(where, ", "))
	}
	return nil
}

// checkInvalid wents over all found adivisories URLs and checks
// if file name confirms to standard.
func (p *processor) checkInvalid(string) error {

	p.badDirListings.use()
	var invalids []string

	for f := range p.alreadyChecked {
		if !util.ConfirmingFileName(filepath.Base(f)) {
			invalids = append(invalids, f)
		}
	}

	if len(invalids) > 0 {
		sort.Strings(invalids)
		p.badDirListings.error("advisories with invalid file names: %s",
			strings.Join(invalids, ", "))
	}

	return nil
}

// checkListing wents over all found adivisories URLs and checks
// if their parent directory is listable.
func (p *processor) checkListing(string) error {

	p.badDirListings.use()

	pgs := pages{}

	var unlisted []string

	badDirs := map[string]struct{}{}

	for f := range p.alreadyChecked {
		found, err := pgs.listed(f, p, badDirs)
		if err != nil && err != errContinue {
			return err
		}
		if !found {
			unlisted = append(unlisted, f)
		}
	}

	if len(unlisted) > 0 {
		sort.Strings(unlisted)
		p.badDirListings.error("Not listed advisories: %s",
			strings.Join(unlisted, ", "))
	}

	return nil
}

// checkProviderMetadata checks provider-metadata.json. If it exists,
// decodes, and validates against the JSON schema.
// According to the result, the respective error messages added to
// badProviderMetadata.
// It returns nil if all checks are passed.
func (p *processor) checkProviderMetadata(domain string) error {

	p.badProviderMetadata.use()

	client := p.httpClient()

	lpmd := csaf.LoadProviderMetadataForDomain(client, domain, p.badProviderMetadata.warn)

	if lpmd == nil {
		p.badProviderMetadata.error("No valid provider-metadata.json found.")
		p.badProviderMetadata.error("STOPPING here - cannot perform other checks.")
		return errStop
	}

	p.pmdURL = lpmd.URL
	p.pmd256 = lpmd.Hash
	p.pmd = lpmd.Document

	return nil
}

// checkSecurity checks the security.txt file by making HTTP request to fetch it.
// It checks the existence of the CSAF field in the file content and tries to fetch
// the value of this field. As a result of these a respective error messages are
// passed to the badSecurity method in case of errors.
// It returns nil if all checks are passed.
func (p *processor) checkSecurity(domain string) error {

	client := p.httpClient()
	p.badSecurity.use()

	path := "https://" + domain + "/.well-known/security.txt"
	res, err := client.Get(path)
	if err != nil {
		p.badSecurity.error("Fetching %s failed: %v", path, err)
		return errContinue
	}

	if res.StatusCode != http.StatusOK {
		p.badSecurity.error("Fetching %s failed. Status code %d (%s)",
			path, res.StatusCode, res.Status)
		return errContinue
	}

	u, err := func() (string, error) {
		defer res.Body.Close()
		lines := bufio.NewScanner(res.Body)
		for lines.Scan() {
			line := lines.Text()
			if strings.HasPrefix(line, "CSAF:") {
				return strings.TrimSpace(line[6:]), nil
			}
		}
		return "", lines.Err()
	}()
	if err != nil {
		p.badSecurity.error("Error while reading security.txt: %v", err)
		return errContinue
	}
	if u == "" {
		p.badSecurity.error("No CSAF line found in security.txt.")
		return errContinue
	}

	// Try to load
	up, err := url.Parse(u)
	if err != nil {
		p.badSecurity.error("CSAF URL '%s' invalid: %v", u, err)
		return errContinue
	}

	base, err := url.Parse("https://" + domain + "/.well-known/")
	if err != nil {
		return err
	}

	u = base.ResolveReference(up).String()
	p.checkTLS(u)
	if res, err = client.Get(u); err != nil {
		p.badSecurity.error("Cannot fetch %s from security.txt: %v", u, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		p.badSecurity.error("Fetching %s failed. Status code %d (%s)",
			u, res.StatusCode, res.Status)
		return errContinue
	}
	defer res.Body.Close()
	// Compare checksums to already read provider-metadata.json.
	h := sha256.New()
	if _, err := io.Copy(h, res.Body); err != nil {
		p.badSecurity.error("Reading %s failed: %v", u, err)
		return errContinue
	}

	if !bytes.Equal(h.Sum(nil), p.pmd256) {
		p.badSecurity.error("Content of %s from security.txt is not "+
			"identical to .well-known/csaf/provider-metadata.json", u)
	}

	return nil
}

// checkPGPKeys checks if the OpenPGP keys are available and valid, fetches
// the the remotely keys and compares the fingerprints.
// As a result of these a respective error messages are passed to badPGP method
// in case of errors. It returns nil if all checks are passed.
func (p *processor) checkPGPKeys(domain string) error {

	p.badPGPs.use()

	src, err := p.expr.Eval("$.public_openpgp_keys", p.pmd)
	if err != nil {
		p.badPGPs.warn("No public OpenPGP keys found: %v.", err)
		return errContinue
	}

	var keys []csaf.PGPKey
	if err := util.ReMarshalJSON(&keys, src); err != nil {
		p.badPGPs.error("Invalid public OpenPGP keys: %v.", err)
		return errContinue
	}

	if len(keys) == 0 {
		p.badPGPs.info("No public OpenPGP keys found.")
		return errContinue
	}

	// Try to load

	client := p.httpClient()

	base, err := url.Parse(p.pmdURL)
	if err != nil {
		return err
	}

	for i := range keys {
		key := &keys[i]
		if key.URL == nil {
			p.badPGPs.error("Missing URL for fingerprint %x.", key.Fingerprint)
			continue
		}
		up, err := url.Parse(*key.URL)
		if err != nil {
			p.badPGPs.error("Invalid URL '%s': %v", *key.URL, err)
			continue
		}

		u := base.ResolveReference(up).String()
		p.checkTLS(u)

		res, err := client.Get(u)
		if err != nil {
			p.badPGPs.error("Fetching public OpenPGP key %s failed: %v.", u, err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			p.badPGPs.error("Fetching public OpenPGP key %s status code: %d (%s)",
				u, res.StatusCode, res.Status)
			continue
		}

		ckey, err := func() (*crypto.Key, error) {
			defer res.Body.Close()
			return crypto.NewKeyFromArmoredReader(res.Body)
		}()

		if err != nil {
			p.badPGPs.error("Reading public OpenPGP key %s failed: %v", u, err)
			continue
		}

		if !strings.EqualFold(ckey.GetFingerprint(), string(key.Fingerprint)) {
			p.badPGPs.error("Fingerprint of public OpenPGP key %s does not match remotely loaded.", u)
			continue
		}
		keyring, err := crypto.NewKeyRing(ckey)
		if err != nil {
			p.badPGPs.error("Creating store for public OpenPGP key %s failed: %v.", u, err)
			continue
		}
		p.keys = append(p.keys, keyring)
	}

	if len(p.keys) == 0 {
		p.badPGPs.info("No OpenPGP keys loaded.")
	}
	return nil
}

// checkWellknownMetadataReporter checks if the provider-metadata.json file is
// available under the /.well-known/csaf/ directory.
// It returns nil if all checks are passed, otherwise error.
func (p *processor) checkWellknownMetadataReporter(domain string) error {

	client := p.httpClient()

	p.badWellknownMetadata.use()

	path := "https://" + domain + "/.well-known/csaf/provider-metadata.json"

	res, err := client.Get(path)
	if err != nil {
		p.badWellknownMetadata.error("Fetching %s failed: %v", path, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		p.badWellknownMetadata.error("Fetching %s failed. Status code %d (%s)",
			path, res.StatusCode, res.Status)
		return errContinue
	}

	return nil
}

// checkDNSPathReporter checks if the "csaf.data.security.domain.tld" DNS record is available
// and serves the "provider-metadata.json".
// It returns nil if all checks are passed, otherwise error.
func (p *processor) checkDNSPathReporter(domain string) error {

	client := p.httpClient()

	p.badDNSPath.use()

	path := "https://csaf.data.security." + domain
	res, err := client.Get(path)
	if err != nil {
		p.badDNSPath.error("Fetching %s failed: %v", path, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		p.badDNSPath.error("Fetching %s failed. Status code %d (%s)",
			path, res.StatusCode, res.Status)
		return errContinue
	}
	hash := sha256.New()
	defer res.Body.Close()
	content, err := io.ReadAll(res.Body)
	if err != nil {
		p.badDNSPath.error("Error while reading the response from %s", path)
		return errContinue
	}
	hash.Write(content)
	if !bytes.Equal(hash.Sum(nil), p.pmd256) {
		p.badDNSPath.error("%s does not serve the same provider-metadata.json as previously found", path)
		return errContinue
	}

	return nil
}
