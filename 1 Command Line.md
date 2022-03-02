# Section 3 Command Line Fun

`echo $PATH`  
`echo $USER`  
`echo $HOME`  
`echo $PWD`  
PATH isn't the only useful environment variable.

`env`  
List all the environment variables.

`export b=10.11.1.220`  
`ping -c 2 $b`  
Use export to declare an environment variable.

`var=10.11.1.220`  
Not globally available in spawned shells. Use export.

`history`  
`!1`  
Display history, and then run command at position 1.

`!!`  
Repeat the last command.

`[CTRL-R]c`
Reverse search. Find the last command used starting with c.

`echo "Create me" > redirection_test.txt`  
Redirect into new file.

`echo "Append me" >> redirection_test.txt`  
Add to end of existing file.

`wc -m < redirection_test.txt`  
File contents becomes the STDIN for `wc`.

`ls ./test 2>error.txt`  
Redirect STDERR.

`cat error.txt | wc -m > count.txt`  
The power of piping.

## Text Searching & Manipulation

`ls -la /usr/bin | grep zip`  
Common switches for grep include `-r` for recursive and `-i` for ignore case.  
https://linux.die.net/man/1/grep

`echo "I need to try hard" | sed 's/hard/harder/'`  
sed is a powerful stream editor.  
https://www.gnu.org/software/sed/manual/sed.html

`echo "I hack binaries,web apps,mobile apps, and just about anything else"| cut -f 2 -d ","`
`cut -d ":" -f 1 /etc/passwd`  
cut is simple and effective. Common switches include `-f` for the field and `-d` for the delimeter.  
https://linux.die.net/man/1/cut

`echo "hello::there::friend" | awk -F "::" '{print $1, $3}'`  
awk is powerful and complex. Use `-F` for the field seperator and `print` for the fields to print.  
cut can only accept a single character as a field delimiter. As a general rule of thumb, when you start having a command involving multiple cut operations, consider switching to awk.

### Practical Example
Take a HTTP access log and filter to just the IP addresses.  
`cat access.log | cut -d " " -f 1 | sort -u`  
Use `uniq` and `sort` to futher refine output and sort the data by the number of times each IP accessed the server. Use `-c` to prefix output line with number of occurences.  
`cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn`  
Filter further to see what address the top IP is accessing:  
`cat access.log | grep '208.68.234.99' | cut -d "\"" -f 2 | uniq -c`  
More details show brute force attack:  
`cat access.log | grep '208.68.234.99' | grep '/admin ' | sort -u`  
Are there any non /admin lines involving that IP?  
`cat access.log|grep '208.68.234.99'| grep -v '/admin '`


