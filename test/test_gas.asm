	.intel_syntax noprefix
.section	.data
	name:  .ascii "have fun\n"
.section	.text
   .globl _start     
_start:             
	
   mov	edx,9      
   lea	ecx, [name] /*This is for reading data section variables. Or we can use: mov ecx, OFFSET FLAT:name*/
   /*mov dword ptr gs:[0x68], ecx
   pcmpistri xmm1, xmm2, 0x2*/
   mov	ebx,1    
   mov	eax,4   
   int	0x80   
	
   mov	eax,1  
   int	0x80  


