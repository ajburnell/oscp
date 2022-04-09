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
