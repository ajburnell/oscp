# Passive Recon

- Names and emails and social media links.
- Whois enumeration - Forward and reverse lookups.
- Google dorking:
	- site:megacorpone.com -filetype:html
	- intitle:"index of" "parent directory"
- Netcraft search:
	- https://searchdns.netcraft.com

## Recon-ng

```bash
recon-ng
marketplace search github
# Require API keys.
marketplace info recon/domains-hosts/google_site_web
marketplace install recon/domains-hosts/google_site_web
modules load recon/domains-hosts/google_site_web
info
options set SOURCE megacorpone.com
marketplace install recon/hosts-hosts/resolve
modules load recon/hosts-hosts/resolve
show hosts
```

## GitHub, GitLab, SourceForge etc.

Search:
user:megacorpone filename:users

Automate searches with Gitrob, Gitleaks or Recon-ng. Access token for API likely required.

Search for things like AWS client ID.

## Other Enumeration

https://www.shodan.io/explore  
https://securityheaders.com/  
https://pastebin.com/  
https://www.ssllabs.com/ssltest/  
https://www.social-searcher.com/  
https://digi.ninja/projects/twofi.php  
https://github.com/initstring/linkedin2username  
Maltego

## Email Harvesting

theHarvester -d megacorpone.com -b google
