# Immunity Debugger

* Upper left window shows assembly instructiouns that make up the application.
  * The highlighted instruction is the one to be executed next. We can see the address it is located at in the process memory space to the left.
* The upper right window containts all the registers.
  * The two we are most interested in are ESP and EIP. EIP should be set to the highlighted instruction in the upper left.
* The lower right window shows the stack and it's content.
  * It shows the memory address, hex data at the address, ASCII representation of data and a dynamic commentary.
  * The data (second column) is displayed as a 32-bit DWORD, dispalyed as four hexadecimal bytes.
  * The highlighted value at the top matches the ESP in the registers.
* Lower left shows memory contents at any given address including address, hex and ASCII representations of data.

* Bottom right shows status, automatically pausing on load at the entry point.
* Execute instructions with F7 (Debug > Step into) or F8 (Debug > Step over).
* Step into will follow the execution flow into a given function call.
* Step over will execute the entire function and return from it.

* Right click in disassembly window. Select Search for > All referenced text strings.
* Double click on a string to go to its location.
* Place a breakpoint using F2. For example at a compare function.
* F9 for Debug > Run.
* Double click on stack address to change to relative offsets.
* Ctrl + F9 for Debug > Execute till return.

General Purpose Registers:
* EAX (accumulator): Arithmetical and logical instructions
* EBX (base): Base pointer for memory addresses
* ECX (counter): Loop, shift, and rotation counter
* EDX (data): I/O port addressing, multiplication, and division
* ESI (source index): Pointer addressing of data and source in string copy operations
* EDI (destination index): Pointer addressing of data and destination in string copy operations

* ESP. Stack pointer for data, poointers and arguments. Dynamic. Keeps track of most recently referenced location on top of stack by storing a pointer to it.
* EBP. Base pointer. Stores a pointer to the top of the stack when a function is called. Allows a function to easily reference info from its own stack frame via offsets while executing. Required arguments, local variables and the return address.
* EIP. Instruction pointer. Next code instruction to be executed. Primary target for attack.

