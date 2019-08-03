section	.text
   global _start     ;must be declared for linker (ld)
_start:             ;tell linker entry point
	
   mov	edx,9       ;message length
   mov	ecx, name   ;message to write
   mov	ebx,1       ;file descriptor (stdout)
   mov	eax,4       ;system call number (sys_write)
   int	0x80        ;call kernel
	
   mov	[name],  dword ' Not'    ; Changed the name
   mov ecx, 100
   mov dword [esp+0x68], ecx
   ;mov dword ds:[0x68], ecx NOT SUPPORTED
	
   mov	edx,8       ;message length
   mov	ecx,name    ;message to write
   mov	ebx,1       ;file descriptor (stdout)
   mov	eax,4       ;system call number (sys_write)
   int	0x80        ;call kernel
	
   mov	eax,1       ;system call number (sys_exit)
   int	0x80        ;call kernel

section	.data
name db 'Have fun'
