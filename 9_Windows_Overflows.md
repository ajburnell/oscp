# Windows Buffer Overflows

In this example we target an application serving HTTP requests on port 80.

* Use SysInternals TCPview tool to identif process number listneing on port 80.
* Must open Immunity Debugger as administrator.
* File > Attach and attach the running process.
* This will pause program execution, resume it by pressing F9.
* Run the python fuzzer against the application.
* Watch for the overflow as EIP points to 41414141.
* Will crash the application - restart in services.

