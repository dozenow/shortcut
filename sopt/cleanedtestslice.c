asm (
".section	.text /*[SLICE_EXTRA] comes with 00000000*/\n"
".globl _section1 /*[SLICE_EXTRA] comes with 00000000*/\n"
"_section1: /*[SLICE_EXTRA] comes with 00000000*/\n"
"mov, ecx, 32 /*[SLICE_EXTRA] comes with b7e8c19a*/\n"
"mov, edi, ecx /*[SLICE_EXTRA] comes with b7e8c19a*/\n"
"mov, #sze1[0xbfffef74], 24 /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"
"mov, #sze1[0xbfffef74], dx /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"
);