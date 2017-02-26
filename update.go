package main

import (
	"bufio"
	"fmt"
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
	sourceURLValidatorMap = map[string]lineValidator{
		`https://raw.githubusercontent.com/vokins/yhosts/master/hosts.txt`:                              hostLine("127.0.0.1"),
		`http://dn-mwsl-hosts.qbox.me/hosts`:                                                            hostLine("191.101.229.116"),
		`https://adaway.org/hosts.txt`:                                                                  hostLine("127.0.0.1"),
		`http://winhelp2002.mvps.org/hosts.txt`:                                                         hostLine("0.0.0.0"),
		`http://hosts-file.net/ad_servers.txt`:                                                          hostLine("127.0.0.1"),
		`https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext`: hostLine("127.0.0.1"),
		`http://sysctl.org/cameleon/hosts`:                                                              hostLine("127.0.0.1"),
		`http://someonewhocares.org/hosts/hosts`:                                                        hostLine("127.0.0.1"),
		`http://www.malwaredomainlist.com/hostslist/hosts.txt`:                                          hostLine("127.0.0.1"),
		`http://www.hostsfile.org/Downloads/hosts.txt`:                                                  hostLine("127.0.0.1"),
		`https://sourceforge.net/projects/adzhosts/files/HOSTS.txt/download`:                            hostLine("127.0.0.1"),
		`https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`:                              hostLine("0.0.0.0"),
		`https://raw.githubusercontent.com/yous/YousList/master/hosts.txt`:                              hostLine("0.0.0.0"),
		`https://download.dnscrypt.org/dnscrypt-proxy/blacklists/domains/mybase.txt`:                    domainListLine(),
		`https://raw.githubusercontent.com/koala0529/adhost/master/adhosts`:                             hostLine("127.0.0.1"),
		`http://hosts-file.net/.%5Cad_servers.txt`:                                                      hostLine("127.0.0.1"),
		`http://mirror1.malwaredomains.com/files/justdomains`:                                           domainListLine(),
		`http://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt`:                                      domainListLine(),
		`https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt`:                          domainListLine(),
		`https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt`:                               domainListLine(),
		`https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt`:                              domainListLine(),
		`https://raw.githubusercontent.com/azet12/KADhosts/master/KADhosts.txt`:                         hostLine("0.0.0.0"),
		`https://raw.githubusercontent.com/lack006/Android-Hosts-L/master/hosts_files/2016_hosts/AD`:    hostLine("127.0.0.1"),
	}
	shortURLs = []string{
		`db.tt`,
		`j.mp`,
		`bit.ly`,
		`goo.gl`,
	}
	whitelist = []whitelistChecker{
		contains(`google-analytics`),
		suffix(`msedge.net`),
		equal(`amazonaws.com`),
		equal(`mp.weixin.qq.com`),
		regex(`^s3[\d\w\-]*.amazonaws.com`),
		suffix(`internetdownloadmanager.com`),
		suffix(`.alcohol-soft.com`),
		equal(`scootersoftware.com`),
		regex(`[^ad]\.mail\.ru`),
		regex(`[^ad]\.daum\.net`),
		regex(`^\w{1,10}\.yandex\.`),
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

type lineValidator func(s string) string

func hostLine(addr string) lineValidator {
	regexPattern := fmt.Sprintf(`^(%s)\s+([\w\d\-\._]+)`, strings.Replace(addr, `.`, `\.`, -1))
	validDomain := regexp.MustCompile(`^((xn--)?[\w\d]+([\w\d\-_]+)*\.)+\w{2,}$`)
	validLine := regexp.MustCompile(regexPattern)
	return func(s string) string {
		ss := validLine.FindStringSubmatch(s)
		if len(ss) > 1 {
			if validDomain.MatchString(ss[2]) {
				return ss[2]
			}
		}
		log.Println("invalid line:", s)
		return ""
	}
}

func domainListLine() lineValidator {
	validDomain := regexp.MustCompile(`^((xn--)?[\w\d]+([\w\d\-_]+)*\.)+\w{2,}$`)
	return func(s string) string {
		if validDomain.MatchString(s) {
			return s
		}
		log.Println("invalid domain:", s)
		return ""
	}
}

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

func matchTLDs(domain string) bool {
	dd := strings.Split(domain, ".")
	lastSection := dd[len(dd)-1]
	if _, ok := tlds[lastSection]; ok {
		return true
	}

	for _, v := range effectiveTLDsNames {
		if strings.HasSuffix(domain, v) {
			return true
		}
	}

	return false
}

func inWhitelist(domain string) bool {
	for _, wl := range whitelist {
		if wl(domain) {
			return true
		}
	}
	return false
}

func process(r io.ReadCloser, validator lineValidator) (domains []string, err error) {
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		// extract valid lines
		domain := validator(strings.ToLower(scanner.Text()))
		if domain == "" {
			continue
		}

		// remove items that don't match TLDs
		if !matchTLDs(domain) {
			log.Println("don't match TLDs:", domain)
			continue
		}

		// remove items in white list
		if inWhitelist(domain) {
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

func getDomains(u string, v lineValidator, domains map[string]bool, wg *sync.WaitGroup) {
	// download hosts
	err := os.ErrNotExist
	var r io.ReadCloser
	for i := 0; i < 10 && err != nil; time.Sleep(5 * time.Second) {
		r, err = downloadRemoteContent(u)
		i++
	}
	if err == nil {
		d, _ := process(r, v)
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
	wg.Add(len(sourceURLValidatorMap))
	for u, v := range sourceURLValidatorMap {
		go getDomains(u, v, domains, &wg)
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
