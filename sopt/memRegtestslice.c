asm (
".section	.text /*[SLICE_EXTRA] comes with 00000000*/\n"
".globl _section1 /*[SLICE_EXTRA] comes with 00000000*/\n"
"_section1: /*[SLICE_EXTRA] comes with 00000000*/\n"
"mov xmmword ptr [0xbfffef74], 2519 /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"
"mov edi, xmmword ptr [0xbfffef76] /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"
"mov edx, 177 /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"
"mov dx, 53 /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"
"mov esp, edx /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"
"mov esp, edi /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"
);
