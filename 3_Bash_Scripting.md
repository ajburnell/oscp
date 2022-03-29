Some example scripts:
```bash
#!/bin/bash
# Hello World Bash Script
echo "Hello World!"
```

Scripts require executable pemissions, `chmod +x hello_world.sh`.

# Variables

`name=value`
```bash
first_name=Good
last_name=Hacker
echo $first_name $last_name
Good Hacker
```

Bash variables are case sensitive. Use descriptive names.

Characters enclosed in single quotes, Bash interprets enclosed characters literally.
Characters in double quotes are viewed literally except $, \`, and \. Variables will be expanded on substitution.

```bash
greeting='$hello'
echo $greeting
hello

greeting2="New $greeting"
echo $greeting2
New $hello

enclose_spaces="Hello World"
```


A variable can be set to the result of a command or program, known as command substitution. This takes what would normally be output to the screen and saves it. Place the variable in parenthesis preceded by a $ character.

```bash
user=$(whoami)
echo $user
kali
```

This substitution happens in a subshell and changes to variables in a subshell will not alter variables from the master process.

Running a script with -x after the shebang allows Bash to print debug output, so we can see commands executed in regular vs subshell.

## Arguments

```
VARIABLE NAME     DESCRIPTION
$0                The name of the Bash script
$1 - $9           The first 9 arguments to the Bash script
$#                Number of arguments passed to the Bash script
$@					      All arguments passed to the Bash script
$?					      The exit status of the most recently run process
$$					      The process ID of the current script
$USER			        The username of the user running the script
$HOSTNAME	        The hostname of the machine
$RANDOM		        A random number
$LINENO		        The current line number in the script
```

You can read user input with the `read` command. `-p` specifies a prompt while `-s` makes the user input silent.

```bash
read -p 'Username: ' username
read -sp 'Password: ' password
```

# If / Else / Elif Statements

```bash
if [ <some test> ]
then
  <perform action>
elif [ <some test> ]
then
  <perform different action>
else
  <perform yet another different action>
fi
```

These can be performed just as an if-then, as an if-then-else, or as the full example above with elif.

Use the following for the tests:
- OPERATOR					DESCRIPTION: EXPRESSION TRUE IF...
- !EXPRESSION			The EXPRESSION is false.
- -n STRING					STRING length is greater than zero
- -z STRING					The length of STRING is zero (empty)
- STRING1 != STRING2	STRING1 is not equal to STRING2
- STRING1 = STRING2		STRING1 is equal to STRING2
- INTEGER1 -eq INTEGER2			INTEGER1 is equal to INTEGER2
- INTEGER1 -ne INTEGER2			INTEGER1 is not equal to INTEGER2
- INTEGER1 -gt INTEGER2			INTEGER1 is greater than INTEGER2
- INTEGER1 -lt INTEGER2			INTEGER1 is less than INTEGER2
- INTEGER1 -ge INTEGER2			INTEGER1 is greater than or equal to INTEGER 2
- INTEGER1 -le INTEGER2			INTEGER1 is less than or equal to INTEGER 2
- -d FILE		FILE exists and is a directory
- -e FILE		FILE exists
- -r FILE		FILE exists and has read permission
- -s FILE		FILE exists and it is not empty
- -w FILE		FILE exists and has write permission
- -x FILE		FILE exists and has execute permission


# Boolean Logical Operators

AND (&&) and OR (||)

The following executes the second command only if the first one succeeds:
```bash
user=kali
grep $user /etc/passwd && echo "$user found!"
kali:x:1000:1000:Kali,,,:/home/kali:/usr/bin/zsh
kali found
```

The OR || only executes if the previous command failed:
```bash
user2=bob
grep $user2 /etc/passwd && echo "$user2 found!" || echo "$user2 not found!"
```

# Loops

## For Loops

```bash
for var-name in <list>
do
  <action to perform>
done
```

The for loop will take each item in the list (in order), assign that item as the value of the variable var-name, perform the given action between do and done, and then go back to the top, grab the next item in the list, and repeat the steps until the list is exhausted.

```bash
for ip in $(seq 1 10); do echo 10.11.1.$ip; done
```
The above uses seq to print 10.11.1.1 all the way to 10.11.1.10. This can also be done using brace expansion.

```bash
for i in {1..10}; do echo 10.11.1.$i; done
# To a file?
for ip in $(seq 1 254); do echo 10.11.1.$ip; done > ips
```

## While Loops
```bash
while [ <some test> ]
do
  <perform an action>
done
```

The below is an example of the off by one error. Change `-lt` to `-le`.
```bash
counter=1

while [ $counter -lt 10 ]
do
  echo "10.11.1.$counter"
  ((counter++))
done
```

# Functions

Functions can be written in two ways:
```bash
function function_name {
commands...
}

function_name () {
commands...
}
```
The only difference being personal preference for the parenthesis.

You can pass arguments to functions:
```bash
#!/bin/bash
# passing arguments to functions

pass_arg() {
  echo "Today's random number is: $1"
}

pass_arg $RANDOM
```

And return them:
```bash
#!/bin/bash
# function return value example

return_me() {
  echo "Oh hello there, I'm returning a random value!"
  return $RANDOM
}

return_me

echo "The previous function returned a value of $?"
```

Note that local variables inside functions can be declared with the keyword `local`.
`local name=test`

# Practical Demonstration

Find all subdomains listed on a web page, and their corresponding IP addresses.

```bash
wget www.megacorpone.com
ls -l index.html
grep "href=" index.html

...
```
Let's use grep to grab lines that contain ".megacorpone", indicating the existence of a subdomain, and grep -v to strip away lines that contain the boring "www.megacorpone.com" domain we already know about:
```bash
grep "href=" index.html | grep "\.megacorpone" | grep -v "www\.megacorpone\.com" | head
```
each line contains a link, and a subdomain, but we need to get rid of the extra HTML around our links. There are always multiple approaches to any task performed in Bash, but we'll use a little-known one for this. We will use the `-F` option of awk to set a multi-character delimiter, unlike cut, which is simple and handy but only allows single-character delimiters. We will set our delimiter to http:// and tell awk we want the second field `('{print $2}')`, or everything after that delimiter:
```bash
grep "href=" index.html | grep "\.megacorpone" | grep -v "www\.megacorpone\.com" | awk -F "http://" '{print $2}'
```
The beginning of each line in our output shows that we're on the right track. Now, we can use cut to set the delimiter to "/" (with -d) and print the first field (with -f 1), leaving us with only the full subdomain name:
```bash
grep "href=" index.html | grep "\.megacorpone" | grep -v "www\.megacorpone\.com" | awk -F "http://" '{print $2}' | cut -d "/" -f 1
```

Or just use a regular expression to improve reliability and errors.
```bash
grep -o '[^/]*\.megacorpone\.com' index.html | sort -u > list.txt
cat list.txt
```

Now get the IP with `host`:
```bash
for url in $(cat list.txt); do host $url; done
```

Grab the IPs only:
```bash
for url in $(cat list.txt); do host $url; done | grep "has address" | cut -d " " -f 4 | sort -u
```

# Practical Demonstration 2

In this example, let's assume we are in the middle of a penetration test and have unprivileged access to a Windows machine. As we continue to collect information, we realize it may be vulnerable to an exploit that we read about that began with the letters a, f, and d but we can't remember the full name of the exploit. In an attempt to escalate our privileges, we want to search for that specific exploit.

Use searchsploit with `-w` to retun the URL instead of local path, and `-t` to search the title:
`searchsploit afd windows -w -t`

`searchsploit afd windows -w -t | grep http | cut -f 2 -d "|"`

Use a bash loop to download the files:

```bash
for e in $(searchsploit afd windows -w -t | grep http | cut -f 2 -d "|"); do exp_name=$(echo $e | cut -d "/" -f 5) && url=$(echo $e | sed 's/exploits/raw/') && wget -q --no-check-certificate $url -O $exp_name; done
```

Or tidy up as a script:
```bash
#!/bin/bash
# Bash script to search for a given exploit and download all matches.

for e in $(searchsploit afd windows -w -t | grep http | cut -f 2 -d "|")

do
  exp_name=$(echo $e | cut -d "/" -f 5)
  url=$(echo $e | sed 's/exploits/raw/')
  wget -q --no-check-certificate $url -O $exp_name
done
```

# Practical Demonstration 3

Let's assume we are tasked with scanning a class C subnet to identify web servers and determine whether or not they present an interesting attack surface. Port scanning is the process of inspecting TCP or UDP ports on a remote machine with the intention of detecting what services are running on the target and potentially what attack vectors exist. In order to accomplish our goal, we would first port scan the entire subnet to pinpoint potential open web services, then we could manually browse their web pages.

This is a pretty straightforward scan, with `-A` for aggressive scanning, `-p` to specify the port or port range, `--open` to only return machines with open ports, and `-oG` to save the scan results in greppable format. Again, don't fret if nmap is new to you. We will go into details later, but nmap certainly provided a decent amount of output to work with.

```bash
mkdir temp
cd temp/

# Scan it
sudo nmap -A -p80 --open 10.11.1.0/24 -oG nmap-scan_10.11.1.1-254

# Grep it
cat nmap-scan_10.11.1.1-254 | grep 80

# Reverse grep to exclude some Nmap lines...
cat nmap-scan_10.11.1.1-254 | grep 80 | grep -v "Nmap"

# Just the IPs now...
cat nmap-scan_10.11.1.1-254 | grep 80 | grep -v "Nmap" | awk '{print $2}'

# Render the page as a PNG... Whoa!
for ip in $(cat nmap-scan_10.11.1.1-254 | grep 80 | grep -v "Nmap" | awk '{print $2}'); do cutycapt --url=$ip --out=$ip.png;done

# Could look through each individually, but why not build a single HTML file with all the basic tags to insert each .PNG into the one web page:

#!/bin/bash
# Bash script to examine the scan results through HTML.

echo "<HTML><BODY><BR>" > web.html

ls -1 *.png | awk -F : '{ print $1":\n<BR><IMG SRC=\""$1""$2"\" width=600><BR>"}' >> web.html

echo "</BODY></HTML>" >> web.html
```
