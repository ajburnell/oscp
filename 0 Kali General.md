# General Kali Commands
`man ls`
Explore the man page for ls command.

`man -k passwd`
A keyword search with man.

`man -k '&passwd$'`
Using a regular expression.

`apropos partition`
Look for commands with 'partition' as part of their decsription. Same same as `man -k`.

`ls -a1`
1 is useful for automation as it lists a single item per line.

`mkdir -p test/{recon,exploit,report}`
Create multiple directories at once.

`echo $PATH`
`which sbd`
which command searches through directories in the PATH environment variable.

`sudo updatedb`
`locate sbd.exe`
locate searches a built in DB that is updated by cron, manually update it with the updatedb command.

`sudo find / -name sbd*`
find is the most flexible and complex. Search recursively from the root file system for any file starting with sbd.

The main advantage of find over locate is that it can search for files and directories by more than just the name. With find, we can search by file age, size, owner, file type, timestamp, permissions, and more.

`sudo systemctl start ssh`
`sudo systemctl start apache2`
Use systemctl to start the SSH / web service.

`sudo ss -antlp | grep sshd`  
`sudo ss -antlp | grep apache`  
Verify the services are running.

`sudo systemctl enable ssh`
`sudo systemctl enable apache2`
Ensure the service starts at boot time.

`systemctl list-unit-files`
View a list of available services.

`sudo apt update`
Update available packages

`sudo apt upgrade`
Upgrade the installed packages. Can specify single packages if need be.
`sudo apt upgrade metasploit-framework`

`apt-cache search pure-ftpd`
Find info stored on a package in the internal package database cache. Searches description rather than package name.

`sudo apt show resource-agents`
Show information in relation to the resource-agents package.

`sudo apt install pure-ftpd`
Install a package

`sudo apt remove --purge`
Removes all package data but leaves modified user config files behind, --purge removes them.

`sudo dpkg -i man-db_2.7.0.2-5_amd64.deb`
dpkg installs a package directly and does not require Internet. It will not install dependencies.













