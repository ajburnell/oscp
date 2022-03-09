8 Web Application Attacks

# Web Application Enumeration

Identify the technology stack:
- Programming language and frameworks
- Web server software
- Database software
- Server operating system

Inspect page content with the Firefox Debugger tool (Ctrl-Shift K).
Find versions of jquery etc.
Use network tab to look at headers and find server details.
Check robots.txt and sitemap.xml.
Check for default administration consoles such as /manager/html for Tomcat or /phpmyadmin for MySQL.

## DIRB
Perform a non-recursive search with a 10 millisecond delay to each request:
`dirb http://www.megacorpone.com -r -z 10`

## Burp

Disable proxy interception on startup under User Options > Misc > Proxy Interception.
Add FoxyProxy Basic (or Standard) to Firefox.
Get a new unique Burp CA for HTTPS:
Proxy > Options > Proxy Listeners > Regenerate CA Certificate.
http://burp.
Save cacert.der.
Drag into Firefox and Trust to identify websites.

## Nikto

Nikto is a highly configurable Open Source web server scanner that tests for thousands of dangerous files and programs, vulnerable server versions and various server configuration issues. It performs well, but is not designed for stealth as it will send many requests and embed information about itself in the User-Agent header.

Nikto can scan multiple servers and ports and will scan as many pages as it can find. On sites with heavy content, such as an ecommerce site, a Nikto scan can take several hours to complete. We have two options to control the scan duration. The simplest option is to set the -maxtime option, which will halt the scan after the specified time limit. This does not optimize the scan in any way. Nikto will simply stop scanning. Our second option is to tune the scan with the -T option. We can use this feature to control which types of tests we want to run. There are times when we do not want to run all the tests built in to Nikto, such as verifying if a certain class of vulnerabilities is present. Tuning a scan is invaluable in these situations.

`nikto -host=http://www.megacorpone.com -maxtime=30s`

## Web Admin Exploitation
ka
Use a pitchfork attack in Burp when a web console requires a unique cookie and token for each request. You can do a recursive grep to get the values from a response and inject into the next request. An example may be defining grep to...
Start with: \_session" value="
Finish with: " />Log
