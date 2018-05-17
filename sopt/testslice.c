asm (
".section	.text /*[SLICE_EXTRA] comes with 00000000*/\n"
".globl _section1 /*[SLICE_EXTRA] comes with 00000000*/\n"
"_section1: /*[SLICE_EXTRA] comes with 00000000*/\n"
"mov ecx, 291 /*[SLICE_EXTRA] comes with b7e8c19a*/\n"
"mov edx, 77 /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"
"mov dx, ecx /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"
"mov edi, edx /*[SLICE] #00000000 [SLICE_INFO] comes with b7e8c19a*/\n"
);