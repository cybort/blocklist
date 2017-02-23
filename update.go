package main

import (
	"bufio"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	urls = []string{
		`https://raw.githubusercontent.com/vokins/yhosts/master/hosts.txt`,
		`http://dn-mwsl-hosts.qbox.me/hosts`,
		`https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt`,
		`https://adaway.org/hosts.txt`,
		`http://winhelp2002.mvps.org/hosts.txt`,
		`http://hosts-file.net/ad_servers.txt`,
		`https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext`,
		`http://sysctl.org/cameleon/hosts`,
		`http://someonewhocares.org/hosts/hosts`,
		`http://www.malwaredomainlist.com/hostslist/hosts.txt`,
		`http://www.hostsfile.org/Downloads/hosts.txt`,
		`https://sourceforge.net/projects/adzhosts/files/HOSTS.txt/download`,
		`https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`,
		`https://raw.githubusercontent.com/yous/YousList/master/hosts.txt`,
		`https://download.dnscrypt.org/dnscrypt-proxy/blacklists/domains/mybase.txt`,
		`https://raw.githubusercontent.com/koala0529/adhost/master/adhosts`,
		`http://hosts-file.net/.%5Cad_servers.txt`,
		`http://mirror1.malwaredomains.com/files/justdomains`,
		`http://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt`,
		`https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt`,
		`https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt`,
		`https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt`,
		`https://raw.githubusercontent.com/azet12/KADhosts/master/KADhosts.txt`,
		`http://someonewhocares.org/hosts/hosts`,
	}
	shortURLs = []string{
		`db.tt`,
		`j.mp`,
		`bit.ly`,
		`goo.gl`,
	}
	whitelist = []whitelistChecker{
		//suffix(`.iqiyi.com`),
		//suffix(`.youku.com`),
		contains(`google-analytics`),
		suffix(`msedge.net`),
		equal(`amazonaws.com`),
	}
	tlds               = make(map[string]bool)
	tldsMutex          sync.Mutex
	effectiveTLDsNames []string
	mutex              sync.Mutex
)

const (
	blocklist                = `toblock.lst`
	blocklistWithoutShortURL = `toblock-without-shorturl.lst`
	tldsURL                  = `http://data.iana.org/TLD/tlds-alpha-by-domain.txt`
	effectiveTLDsNamesURL    = `https://publicsuffix.org/list/effective_tld_names.dat`
)

type whitelistChecker func(s string) bool

func contains(pattern string) whitelistChecker {
	return func(s string) bool {
		return strings.Contains(s, pattern)
	}
}

func suffix(pattern string) whitelistChecker {
	return func(s string) bool {
		return strings.HasSuffix(s, pattern)
	}
}

func prefix(pattern string) whitelistChecker {
	return func(s string) bool {
		return strings.HasPrefix(s, pattern)
	}
}

func equal(pattern string) whitelistChecker {
	return func(s string) bool {
		return pattern == s
	}
}

func regex(pattern string) whitelistChecker {
	r := regexp.MustCompile(pattern)
	return func(s string) bool {
		return r.MatchString(s)
	}
}

func downloadRemoteContent(remoteLink string) (io.ReadCloser, error) {
	response, err := http.Get(remoteLink)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return response.Body, nil
}

func process(r io.ReadCloser) (domains []string, err error) {
	validLine := regexp.MustCompile(`^(127\.0\.0\.1|0\.0\.0\.0|::1)\s+([\w\d\-\._]+)`)
	validDomain := regexp.MustCompile(`^((xn--)?[\w\d]+([\w\d\-_]+)*\.)+\w{2,}$`)
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		// extract valid lines
		domain := strings.ToLower(scanner.Text())
		ss := validLine.FindStringSubmatch(domain)
		if len(ss) <= 1 {
			if !validDomain.MatchString(domain) {
				log.Println("invalid line:", domain)
				continue
			}
		} else {
			domain = ss[2]
		}

		// remove items that don't match xxxx.xxxx.xxxx format
		if !validDomain.MatchString(domain) {
			log.Println("invalid domain:", domain)
			continue
		}

		// remove items that don't match TLDs
		matchTLD := false
		dd := strings.Split(domain, ".")
		lastSection := dd[len(dd)-1]
		_, matchTLD = tlds[lastSection]

		if !matchTLD {
			for _, v := range effectiveTLDsNames {
				if strings.HasSuffix(domain, v) {
					matchTLD = true
					break
				}
			}
		}

		if !matchTLD {
			log.Println("don't match TLDs:", domain)
			continue
		}

		// remove items in white list
		inWhitelist := false
		for _, wl := range whitelist {
			if wl(domain) {
				inWhitelist = true
				break
			}
		}
		if inWhitelist {
			log.Println("in whitelist:", domain)
			continue
		}
		domains = append(domains, domain)
	}
	r.Close()
	return
}

func saveToFile(content string, path string) error {
	file, err := os.OpenFile(path, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0644)
	if err == nil {
		file.WriteString(content)
		file.Close()
		return nil
	}

	log.Println(err)
	return err
}

func generateTLDs(wg *sync.WaitGroup) {
	err := os.ErrNotExist
	var r io.ReadCloser
	for i := 0; i < 10 && err != nil; time.Sleep(5 * time.Second) {
		r, err = downloadRemoteContent(tldsURL)
		i++
	}
	if err == nil {
		scanner := bufio.NewScanner(r)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			tldsMutex.Lock()
			tlds[strings.ToLower(scanner.Text())] = true
			tldsMutex.Unlock()
		}
		r.Close()
	}
	wg.Done()
}

func generateEffectiveTLDsNames(wg *sync.WaitGroup) {
	err := os.ErrNotExist
	var r io.ReadCloser
	for i := 0; i < 10 && err != nil; time.Sleep(5 * time.Second) {
		r, err = downloadRemoteContent(effectiveTLDsNamesURL)
		i++
	}
	if err == nil {
		scanner := bufio.NewScanner(r)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			line := strings.ToLower(scanner.Text())
			if len(line) == 0 {
				continue
			}
			c := line[0]
			if c >= byte('a') && c <= byte('z') || c >= byte('0') && c <= byte('9') {
				if strings.IndexByte(line, byte('.')) < 0 {
					tldsMutex.Lock()
					tlds[line] = true
					tldsMutex.Unlock()
				} else {
					effectiveTLDsNames = append(effectiveTLDsNames, "."+line)
				}
			}
		}
		r.Close()
	}
	wg.Done()
}

func getDomains(u string, domains map[string]bool, wg *sync.WaitGroup) {
	// download hosts
	err := os.ErrNotExist
	var r io.ReadCloser
	for i := 0; i < 10 && err != nil; time.Sleep(5 * time.Second) {
		r, err = downloadRemoteContent(u)
		i++
	}
	if err == nil {
		d, _ := process(r)
		for _, domain := range d {
			// so could remove duplicates
			mutex.Lock()
			domains[domain] = true
			mutex.Unlock()
		}
	}
	wg.Done()
}

func main() {
	var wg sync.WaitGroup
	wg.Add(2)
	go generateTLDs(&wg)
	go generateEffectiveTLDsNames(&wg)
	wg.Wait()

	domains := make(map[string]bool)
	wg.Add(len(urls))
	for _, u := range urls {
		go getDomains(u, domains, &wg)
	}
	wg.Wait()

	for _, v := range shortURLs {
		delete(domains, v)
	}
	d := make([]string, len(domains))
	i := 0
	for k := range domains {
		d[i] = k
		i++
	}
	sort.Strings(d)
	// extract domain names
	c := strings.Join(d, "\n")
	saveToFile(c, blocklistWithoutShortURL)
	d = append(d, shortURLs...)
	sort.Strings(d)
	c = strings.Join(d, "\n")
	saveToFile(c, blocklist)
}
