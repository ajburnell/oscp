# Privilege Escalation

## Enumeration
`

## Windows Privilege Escalation
```cmd
whoami
# List more information about user
net user <result of whoami>
# List all accounts and gather more info
net user 
# Get hostname
hostname
# Get system information and extract particular bits of information
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
# Enumerate running processes
tasklist /SVC
# Enumerate networking
ipconfig /all
route print
# a for active TCP connections, n for address and port number numerically, o for the owning process ID.
netstate -ano
# Check firewall
netsh advfirewall show currentprofile
# If firewall is active
netsh advfirewall firewall show rule name=all
# Check for scheduled tasks
# /query displays tasks, /fo list outputs a simple list, and /v for verbose
schtasks /query /fo LIST /v
# Enumerate installed applications and patch levels
wmic product get name, version, vendor
wmic qfe get Caption, Description, HotFixID, InstalledOn
# Enumerate read/writeable files and directories
# -u suppress errors, -w search for write permissions, -s for recursive search.
accesschk.exe -uws "Everyone" "C:\Program Files"
# Similar but with PowerShell. Get-ChildItem is used to do search recursively and then check the permissions with Get-ACL.
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
# Enumerate unmounted disks
mountvol
# Enumerate device drivers and kernel modules
# Powershell /v for verbose, /fo csv to request in CSV format.
powershell
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
# Check binaries that AutoElevate. If enabled an MSI could be crafter to elevate privileges.
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer

## Linux Privilege Escalation
```bash
id
# Look for other users and clues to services installed, e.g. web, db, dc...
cat /etc/passwd
# Get hostname
hostname
# Get system information.
cat /etc/issue
cat /etc/*-release
uname -a
# Enumerate running processes
# a and x for processes with and without tty, u for user readable.
ps axu
# Enumerate networking
ifconfig a
# or
ip a
/sbin/route
# a for all connections, n to avoid hostname resolution, p to list the process name
netstat -anp
# or
ss -anp
# iptables on Linux requires root privileges but check:
/etc/iptables
# grep /etc for  iptables-save and iptables-restore files.
# Check for scheduled tasks
ls -lah /etc/cron*
cat /etc/crontab
# Enumerate installed applications
dpkg -l
# Enumerate read/writeable files and directories
# Use -writeable to find write access, and -d to locate directories, and 2>/dev/null to pipe errors away.
find / -writable -type d 2>/dev/null
# Enumerate unmounted disks
cat /etc/fstab 
mount
/bin/lsblk
# Enumerate devices and drivers
lsmod
# Query a result from the above. This tool requires full pathname.
/sbin/modinfo libata
# Enumerate elevated binaries. Binaries with SUID bit set take on the persmission of the file owner.
# Look for files from root directory of -type f (file) with SUID bit set. Discard errors
find / -perm -u=s -type f 2>/dev/null
