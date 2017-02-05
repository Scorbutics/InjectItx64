EXTERN LoadLibraryA proc

.code

LoadLibraryInMemx64 proc
	
	PUSH RCX
	PUSH RDX
	PUSH RDI
	
	;The second parameter passed to LoadLibraryInMemx64 is the address where we'll stock
	;the LoadLibraryA returned value, and we copy it to RDI
	MOV RDI, RDX


	CALL LoadLibraryA

	;Let's copy the Handle returned by LoadLibraryA in a memory Zone
	MOV QWORD PTR[RDI], RAX
	
	POP RDI
	POP RDX
	POP RCX
	
	
LoadLibraryInMemx64 endp

LoadLibraryInMemx86 proc

	PUSH EDI

	CALL LoadLibraryA
	MOV DWORD PTR[EDI], EAX

	POP EDI

LoadLibraryInMemx86 endp

end