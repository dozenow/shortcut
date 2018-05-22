asm (
".section	.text /*[SLICE_EXTRA] comes with 00000000*/\n"
".globl _section1 /*[SLICE_EXTRA] comes with 00000000*/\n"
"_section1: /*[SLICE_EXTRA] comes with 00000000*/\n"
"mov word ptr [0xbfffef74], 2519 /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"
"mov edi, byte ptr [0xbfffef75] /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"
"mov eax, 177 /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"
"mov ax, 53 /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"	
"mov ah, 25 /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"
"mov esp, eax /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"
"mov esp, edi /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"
);
