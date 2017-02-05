Basic Injector running on x64 machines that is able to load into x64 AND x86 processes.
You'll of course need a DLL compiled in the correct architecture (x86 if the target process is in x86, x64 if the target process is in x64).

To use it :

InjectItx64.exe cmd.exe -iCS mydll.dll

It will inject the dll "mydll.dll" in a "cmd.exe" instance newly created.
The "-iCS" attribute stands for "Create Suspended", which means that the process "cmd.exe" has to be created, then suspended, then the "mydll.dll" loaded into it, then resumed.
