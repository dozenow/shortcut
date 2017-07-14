#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main (int arc, char* argv[])
{
  FILE* file1, *file2;
  char line1[256], line2[256];

  file1 = fopen (argv[1], "r");
  if (file1 == NULL) {
      fprintf (stderr, "Cannot open %s\n", argv[1]);
      return -1;
  }
  file2 = fopen (argv[2], "r");
  if (file2 == NULL) {
      fprintf (stderr, "Cannot open %s\n", argv[2]);
      return -1;
  }

  if (fgets (line1, sizeof(line1), file1) == NULL) {
      fprintf (stderr, "%s is empty\n", argv[1]);
      return -1;
  }

  if (fgets (line2, sizeof(line2), file2) == NULL) {
      fprintf (stderr, "%s is empty\n", argv[2]);
      return -1;
  }

  u_long linecnt = 1;
  while (!(feof (file1) && feof(file2))) {
      bool is_equal = false;
      if (!strcmp(line1, line2)) {
	  is_equal = true;
      } else {
	  // If two lines are equivalent up to first value, that is OK
	  char* v1 = strstr (line1, "value");
	  char* v2 = strstr (line2, "value");
	  if (v1 && v2) {
	      *v1 = '\0';
	      *v2 = '\0';
	      if (!strcmp(line1, line2)) {
		  is_equal = true;
	      }
	  }
      } 

      if (is_equal) {
	  fgets (line1, sizeof(line1), file1);
	  fgets (line2, sizeof(line2), file2);
	  linecnt++;
      } else {
	  printf ("line %8lu: %s           vs. %s\n", linecnt, line1, line2);
	  // Should I quit or keep going?
	  fgets (line1, sizeof(line1), file1);
	  fgets (line2, sizeof(line2), file2);
	  linecnt++;
      }
  }
		
  fclose (file1);
  fclose (file2);
  return 0;
}
  
