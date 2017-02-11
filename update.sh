#!/bin/bash
echo "" > toblock.lst
#curl -s https://raw.githubusercontent.com/vokins/yhosts/master/hosts.txt | grep -v "^#" | grep "127.0.0.1" | grep -v "\.iqiyi\.com" | grep -v "\.youku\.com" | grep -v "google\-analytics" | awk '{print $2}' > toblock.lst
curl -s http://dn-mwsl-hosts.qbox.me/hosts | grep -v "^#" | grep "181.215.102.78"  | grep -v "\.iqiyi\.com" | grep -v "\.youku\.com" | grep -v "google\-analytics"  | awk '{print $2}' >> toblock.lst
curl -s https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt | grep -v "^#" | grep -v "\.iqiyi\.com" | grep -v "\.youku\.com" | grep -v "google\-analytics"  >> toblock.lst
curl -s https://adaway.org/hosts.txt | grep -v "^#" | grep "127.0.0.1"   | grep -v "\.iqiyi\.com" | grep -v "\.youku\.com" | grep -v "google\-analytics" | awk '{print $2}' >> toblock.lst
curl -s http://winhelp2002.mvps.org/hosts.txt | grep -v "^#" | grep "0.0.0.0"  | grep -v "\.iqiyi\.com" | grep -v "\.youku\.com" | grep -v "google\-analytics" | awk '{print $2}' >> toblock.lst
curl -s http://hosts-file.net/ad_servers.txt | grep -v "^#" | grep "127.0.0.1"  | grep -v "\.iqiyi\.com" | grep -v "\.youku\.com" | grep -v "google\-analytics"  | awk '{print $2}' >> toblock.lst
curl -s "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext" | grep -v "^#" | grep "127.0.0.1"  | grep -v "\.iqiyi\.com" | grep -v "\.youku\.com" | grep -v "google\-analytics"  | awk '{print $2}' >> toblock.lst
curl -s http://sysctl.org/cameleon/hosts | grep -v "^#" | grep "127.0.0.1"  | grep -v "\.iqiyi\.com" | grep -v "\.youku\.com" | grep -v "google\-analytics"  | awk '{print $2}' >> toblock.lst
curl -s http://someonewhocares.org/hosts/hosts | grep -v "^#" | grep "127.0.0.1"  | grep -v "\.iqiyi\.com" | grep -v "\.youku\.com" | grep -v "google\-analytics"  | awk '{print $2}' >> toblock.lst
curl -s http://www.malwaredomainlist.com/hostslist/hosts.txt  | grep -v "^#" | grep "127.0.0.1"  | grep -v "\.iqiyi\.com" | grep -v "\.youku\.com" | grep -v "google\-analytics"  | awk '{print $2}' >> toblock.lst
curl -s http://www.hostsfile.org/Downloads/hosts.txt | grep -v "^#" | grep "127.0.0.1"  | grep -v "\.iqiyi\.com" | grep -v "\.youku\.com" | grep -v "google\-analytics"  | awk '{print $2}' >> toblock.lst
curl -s "http://adblock.gjtech.net/?format=unix-hosts" | grep -v "^#" | grep "127.0.0.1"  | grep -v "\.iqiyi\.com" | grep -v "\.youku\.com" | grep -v "google\-analytics"  | awk '{print $2}' >> toblock.lst
curl -s http://optimate.dl.sourceforge.net/project/adzhosts/HOSTS.txt | grep -v "^#" | grep "127.0.0.1"  | grep -v "\.iqiyi\.com" | grep -v "\.youku\.com" | grep -v "google\-analytics"  | awk '{print $2}' >> toblock.lst
curl -s -L https://github.com/StevenBlack/hosts/raw/master/hosts | grep -v "^#" | grep "0.0.0.0" | grep -v "\.iqiyi\.com" | grep -v "\.youku\.com" | grep -v "google\-analytics"  | awk '{print $2}' >> toblock.lst
curl -s -L https://github.com/yous/YousList/raw/master/hosts.txt | grep -v "^#" | grep "127.0.0.1"   | grep -v "\.iqiyi\.com" | grep -v "\.youku\.com" | grep -v "google\-analytics" | awk '{print $2}' >> toblock.lst
sed -i 's/telemetry.appex.bing.net:443/telemetry.appex.bing.net/g' toblock.lst
sed -i 's/ssl-nl.persgroep.edgekey.neto/ssl-nl.persgroep.edgekey.net/g' toblock.lst
sed -i 's/ssl-nl.persgroep.edgekey.netO/ssl-nl.persgroep.edgekey.net/g' toblock.lst
sed -i 's/theoads.com./theoads.com/g' toblock.lst
sed -i '/130.211.230.53/d' toblock.lst
sed 's/\r$//' toblock.lst | sort -n | uniq  > toblock.new
mv toblock.new toblock.lst
