asm (
".section	.text\n"
".globl _section1\n"
"_section1:\n"
"mov ecx, 17\n"
"mov dword ptr [0xbffff38c], ecx\n"
"call handle_index_diverge\n"
"mov eax, 5\n"
"mov ecx, dword ptr [0xbffff38c]\n"
"call handle_index_diverge\n"
);
