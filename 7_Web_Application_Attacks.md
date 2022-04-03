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

* Disable proxy interception on startup under User Options > Misc > Proxy Interception.
* Add FoxyProxy Basic (or Standard) to Firefox.
* Get a new unique Burp CA for HTTPS:
  * Proxy > Options > Proxy Listeners > Regenerate CA Certificate.
  * http://burp.
  * Save cacert.der.
  * Firefox > Settings > Privacy & Security > View Certificates > Import.
  * Enjoy HTTPS goodness without errors.

## Nikto

Nikto is a highly configurable Open Source web server scanner that tests for thousands of dangerous files and programs, vulnerable server versions and various server configuration issues.

The -maxtime option will halt the scan after the specified time limit. This does not optimize the scan in any way. Nikto will simply stop scanning. Tune the scan with the -T option. We can use this feature to control which types of tests we want to run. There are times when we do not want to run all the tests built in to Nikto, such as verifying if a certain class of vulnerabilities is present. Nikto can be slow on large websites and is not stealthy as it sends so many requests, as well as identifying itself in the User-Agent header.

`nikto -host=http://www.megacorpone.com -maxtime=30s`

## Web Admin Exploitation Example

https://en.wikipedia.org/wiki/Cross-site_request_forgery#Synchronizer_token_pattern

Example of Burp and phpMyAdmin. Even though you can't use Burp in the exam...

1. Submit a login request for for intruder to analyse.
2. Right click on the POST request in Burp and send to intruder.
3. On the positions tab clear all set positions and add the cookie, set_session, token and password.
4. Select pitchfork attack type so we can use different values for each position. https://portswigger.net/burp/documentation/desktop/tools/intruder/attack-types
  * The attack iterates through all payload sets simultaneously, and places one payload into each defined position. In other words, the first request will place the first payload from payload set 1 into position 1 and the first payload from payload set 2 into position 2; the second request will place the second payload from payload set 1 into position 1 and the second payload from payload set 2 into position 2, etc. 
5. Under options navigate to Grep -Extract which will save results of a request and make them available for the next one. Highlight the area of the token or set_session and it will extract the field.
6. Navigate to payloads. Add the recursive greps and the password.
7. Start attack.
8. Identify the 302 different response. Login with same password.
9. Run SQL query:
   * `select * from webappdb.users;`
   * `insert into webappdb.users(password, username) VALUES ("backdoor","backdoor");`
