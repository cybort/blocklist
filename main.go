package main

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
		`http://optimate.dl.sourceforge.net/project/adzhosts/HOSTS.txt`,
		`https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`,
		`https://raw.githubusercontent.com/yous/YousList/master/hosts.txt`,
	}
	shortURLs = []string{
		`db.tt`,
		`j.mp`,
		`bit.ly`,
		`goo.gl`,
	}
)

func download(u string) []byte {
	return nil
}

func extractDomainNames(raw []byte) []string {
	// remove items that don't match xxxx.xxxx.xxxx format
	// remove items that don't match TLDs
	// remove duplicate items
	// remove items in white list
	return nil
}

func saveToFile(domains []string) error {
	return nil
}

func main() {
	for _, u := range urls {
		// download hosts
		content := download(u)
		// extract domain names
		domains := extractDomainNames(content)

		saveToFile(domains)
	}
}
