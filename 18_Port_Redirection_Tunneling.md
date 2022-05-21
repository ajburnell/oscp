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

Remote port forwarding using SSH:  
ssh to kali machine `kali@192.168.119.208` with `-N` for no commands, and `-R` for remote forward. Open a listener on kali machine `2221` and forward connections to the internal Linux TCP port `3306` with `128.0.0.1:3306`,
```bash
ssh -N -R [bind_address:]port:host:hostport [username@address]

ssh -N -R 192.168.119.208:2221:127.0.0.1:3306 kali@192.179.119.208

# Reverse bind from local to remote:
sh -N -R 192.168.208.52:5555:127.0.0.1:2221 student@192.168.208.52 -p 2222

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
