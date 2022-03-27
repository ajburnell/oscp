# DNS

- NS - Nameserver records contain the name of the authoritative servers hosting the DNS records for a domain.
- A - Also known as a host record, the "a record" contains the IP address of a hostname (such as www.megacorpone.com).
- MX - Mail Exchange records contain the names of the servers responsible for handling email for the domain. A domain can contain multiple MX records.
- PTR - Pointer Records are used in reverse lookup zones and are used to find the records associated with an IP address.
- CNAME - Canonical Name Records are used to create aliases for other host records.
- TXT - Text records can contain any arbitrary data and can be used for various purposes, such as domain ownership verification.

- `host www.megacorpone.com`
- `host -t mx megacorpone.com`
- `host -t txt megacorpone.com`

## Forward Lookup Brute Force

`for ip in $(cat list.txt); do host $ip.megacorpone.com; done`

## Reverse Lookup Brute Force

`for ip in $(seq  50 100); do host 38.100.193.$ip; done | grep -v "not found"`

## Zone Transfer

`host -l <domain name> <dns server address>`

To get both the domain name and dns server:
`host -t ns megacorpone.com | cut -d " " -f 4`

```bash
#!/bin/bash

# Simple Zone Transfer Bash Script
# $1 is the first argument given after the bash script
# Check if argument was given, if not, print usage

if [ -z "$1" ]; then
  echo "[*] Simple Zone transfer script"
  echo "[*] Usage   : $0 <domain name> "
  exit 0
fi

# if argument was given, identify the DNS servers for the domain

for server in $(host -t ns $1 | cut -d " " -f4); do
  # For each of these servers, attempt a zone transfer
  host -l $1 $server |grep "has address"
done
```

## DNSRecon & DNSEnum
Perform a zone transfer with DNS recon:  
`dnsrecon -d megacorpone.com -t axfr`

Brute forcing hostnames wsith dnsrecon:  
`dnsrecon -d megacorpone.com -D /usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top500.txt -t brt`

DNS Enumeration with dnsenum:  
`dnsenum megacorpone.com`

If we do not know any of the hostnames we can enumerate for local DNS servers:  
`sudo nmap -v -p 53 192.168.0.0/24`  
We can then perform an nmap scan and try and resolve services using a specific domain server, such as one we just discovered with the above command:  
`sudo nmap -sL -v --dns-server 192.168.0.100 192.168.0.0/24`  
We can then make a query on a found domain name, again specifying that name server:  
`dig @192.168.0.100 example.com ANY`  
`dnsrecon --dnsserver 192.168.0.100 example.com` OR  
`dnsenum -n 191.168.0.100 -d example.com`

## Querying Multiple Sites
`cat sites.txt | while read line; do dig -t TXT $line; done`

# Port Scanning

Netcat for the basics:

TCP port scan:
`nc -nvv -w 1 -z 10.11.1.220 3388-3390`

UDP port scan:
`nc -nv -u -z -w 1 10.11.1.115 160-162`

Bit of an aside to measure traffic that is used with nmap. First, we will use the -I option to insert a new rule into a given chain, which in this case includes both the INPUT (Inbound) and OUTPUT (Outbound) chains followed by the rule number. We will use -s to specify a source IP address, -d to specify a destination IP address, and -j to ACCEPT the traffic. Lastly, we will use the -Z option to zero the packet and byte counters in all chains.

```bash
sudo iptables -I INPUT 1 -s 10.11.1.220 -j ACCEPT
sudo iptables -I OUTPUT 1 -d 10.11.1.220 -j ACCEPT
sudo iptables -Z

nmap 10.11.1.220

sudo iptables -vn -L
# 78 KB
sudo iptables -Z

nmap -p 1-65535 10.11.1.220

sudo iptables -vn -L
# 4MB!
```

**SYN / Stealth scanning**:
`sudo nmap -sS 10.11.1.220`
No privileges, defaults to TCP Connect. Much slower:
`nmap -sT 10.11.1.220`
**UDP,** requires privileges:
`sudo nmap -sU 10.11.1.115`
Combine a SYN and a UDP scan:
`sudo nmap -sS -sU 10.11.1.115`
**Network sweep** odes more than ICMP. Sends a SYN packet to 443 and an ACK packet to port 80. 
`nmap -sn 10.11.1.1-254`

Easier to scan and output to greppable format and then grep the results:
`nmap -v -sn 10.11.1.1-254 -oG ping-sweep.txt`
`grep Up ping-sweep.txt | cut -d " " -f 2`

Sweeping for specific ports across a network can be more accurate then a ping swep:
`nmap -p 80 10.11.1.1-254 -oG web-sweep.txt`
`grep open web-sweep.txt | cut -d" " -f2`

You can save time by scanning multiple IPs with a short-list of common ports. The below conducts a TCP connect scan for the top twenty TCP ports, including OS version detection, script scanning and traceroute with -A:
`nmap -sT -A --top-ports=20 10.11.1.1-254 -oG top-port-sweep.txt`

The top ports are based on:
`cat /usr/share/nmap/nmap-services`

You can grab banners with: (Service Banners, TCP connect, Service enumeration -A)
`nmap -sV -sT -A 10.11.1.220`

Scripts contained in the /usr/share/nmap/scripts directory can be ran:
`nmap 10.11.1.220 --script=smb-os-discovery`
`nmap --script=dns-zone-transfer -p 53 ns2.megacorpone.com`

Script help can help us if we are lost:
`nmap --script-help dns-zone-transfer`

Masscan is fast!
Examples include -rate to specify packet transmission rate, -e to specify the raw network interface to use, and --router-ip to specify the gateway.
```bash
sudo apt install masscan
sudo masscan -p80 10.0.0.0/8
sudo masscan -p80 10.11.1.0/24 --rate=1000 -e tap0 --router-ip 10.11.0.1
```

# SMB Enumeration

Scan for the NetBIOS service. Note SMB on TCP 445 is ifferent to the NetBIOS service listning on TCP 139.

`nmap -v -p 139,445 -oG smb.txt 10.11.1.1-254`

`nbtscan` is anoher specialised tool for identifying NetBIOS information.
`sudo nbtscan -r 10.11.1.0/24'`

SMB enumeration with nmap:
`ls -1 /usr/share/nmap/scripts/smb*`

`nmap -v -p 139, 445 --script=smb-os-discovery 10.11.1.227`

`nmap -v -p 139,445 --script=smb-vuln-ms08-067 --script-args=unsafe=1 10.11.1.5`

# NFS Enumeration

`nmap -v -p 111 10.11.1.1-254`

`nmap -sV -p 111 --script=rpcinfo 10.11.1.1-254`

`ls -1 /usr/share/nmap/scripts/nfs*`

`nmap -p 111 --script nfs* 10.11.1.72`

Find an open share? Mount it!
`mkdir home
sudo mount -o nolock 10.11.1.72:/home ~/home/
cd home/ && ls`

Say there are files that you can't access as you are not the right user? Make a right user!

`ls -la` Get UUID.
```bash
sudo adduser pwn
sudo sed -i -e 's/1001/1014/g' /etc/passwd 
cat /etc/passwd | grep pwn
su pwn
id
```

# SMTP Enumeration

The Simple Mail Transport Protocol (SMTP)1 supports several interesting commands, such as VRFY and EXPN. A VRFY request asks the server to verify an email address, while EXPN asks the server for the membership of a mailing list. These can often be abused to verify existing users on a mail server, which is useful information during a penetration test. Consider this example:
```bash
nc -nv 10.11.1.217 25
(UNKNOWN) [10.11.1.217] 25 (smtp) open
220 hotline.localdomain ESMTP Postfix
VRFY root
252 2.0.0 root
VRFY idontexist
550 5.1.1 <idontexist>: Recipient address rejected: User unknown in local recipient table
```

Notice how the success and error messages differ. The SMTP server happily verifies that the user exists. This procedure can be used to help guess valid usernames in an automated fashion. Consider the following Python script that opens a TCP socket, connects to the SMTP server, and issues a VRFY command for a given username:
```python
#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 2:
        print "Usage: vrfy.py <username>"
        sys.exit(0)

# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the Server
connect = s.connect(('10.11.1.217',25))

# Receive the banner
banner = s.recv(1024)

print banner

# VRFY a user
s.send('VRFY ' + sys.argv[1] + '\r\n')
result = s.recv(1024)

print result

# Close the socket
s.close()
```

# SNMP Enumeration

`sudo nmap -sU --open -p 161 10.11.1.1-254 -oG open-snmp.txt`

Use onesixtyone to brute force:
```bash
echo public > community
echo private >> community
echo manager >> community
for ip in $(seq 1 254); do echo 10.11.1.$ip; done > ips
onesixtyone -c community -i ips
```
http://www.phreedom.org/software/onesixtyone/

This command enumerates the entire MIB tree using the -c option to specify the community string, and -v to specify the SNMP version number as well as the -t 10 to increase the timeout period to 10 seconds:
`snmpwalk -c public -v1 -t 10 10.11.1.14`

Enumerate windows users:
`snmpwalk -c public -v1 10.11.1.14 1.3.6.1.4.1.77.1.2.25`

Enumerate running processes:
`snmpwalk -c public -v1 10.11.1.73 1.3.6.1.2.1.25.4.2.1.2`

Open TCP ports:
`snmpwalk -c public -v1 10.11.1.14 1.3.6.1.2.1.6.13.1.3`

Installed software:
`snmpwalk -c public -v1 10.11.1.50 1.3.6.1.2.1.25.6.3.1.2`

snmp-check is another piece of similar software.
