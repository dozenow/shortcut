#include <stdio.h>
#include <stdlib.h>

int main (int argc, char* argv[])
{
    FILE* file1 = fopen(argv[1], "r");
    if (file1 == NULL) {
	fprintf (stderr, "Cannot open %s\n", argv[1]);
	return -1;
    } 

    FILE* file2 = fopen(argv[2], "r");
    if (file2 == NULL) {
	fprintf (stderr, "Cannot open %s\n", argv[2]);
	return -1;
    } 

    char buf1[65536], buf2[65536];
    while (!feof(file1)) {
	u_long syscall1, syscall2;
	u_long start1, start2;
	u_long end1, end2;
	long retval1, retval2;
	
	// Check headers
	if (fscanf (file1, "syscall %lu clock %lu %lu retval %ld\n", &syscall1, &start1, &end1, &retval1) != 4) {
	    fprintf (stderr, "Cannot read syscall line from %s\n", argv[1]);
	    return -1;
	}
	if (fscanf (file2, "syscall %lu clock %lu %lu retval %ld\n", &syscall2, &start2, &end2, &retval2) != 4) {
	    fprintf (stderr, "Cannot read syscall line from %s\n", argv[2]);
	    return -1;
	}
	if (retval1 != retval2) {
	    printf ("syscall %lu/%lu clock <%lu:%lu>/<%lu:%lu> returns differnet values: %ld vs %ld\n",
		     syscall1, syscall2, start1, end1, start2, end2, retval1, retval2);
	}

	if (retval1 < 0) continue;

	// Check body
	if (fgets (buf1, sizeof(buf1), file1) < 0) {
	    fprintf (stderr, "Cannot read from %s\n", argv[1]);
	    return -1;
	} 
	if (fgets (buf2, sizeof(buf2), file2) < 0) {
	    fprintf (stderr, "Cannot read from %s\n", argv[2]);
	    return -1;
	} 
	
	bool differ = false;
	for (int i = 0; i < retval1; i++) {
	    if (buf1[2*i] != buf2[2*i] || buf1[2*i+1] != buf2[2*i+1]) {
		if (!differ) {
		    printf ("syscall %lu/%lu: differ at bytes ", syscall1, syscall2);
		    differ = true;
		}
		printf ("%d ", i);
	    } 
	}
	if (differ) printf ("\n\n");
    } 
		    
    return 0;
}
