#include <stdio.h>
#include <stdlib.h>

#ifdef bitmap_64
  #define bitmap_type unsigned long long int
  #define bitmap_shift        6
  #define bitmap_mask        63
  #define bitmap_wordlength  64
  #define bitmap_fmt "%016llx"
#else	// assumed to be 32 bits
  #define bitmap_type unsigned int
  #define bitmap_shift        5
  #define bitmap_mask        31
  #define bitmap_wordlength  32
  #define bitmap_fmt "%08x"
#endif

// get the types right
#define bitmap_one        (bitmap_type)1

typedef struct {
  int bits;	// number of bits in the array
  int words;	// number of words in the array
  bitmap_type *array;
} bitmap;

//expand the size
void bitmap_expand(bitmap* b, int new_bits) { 
	int new_words = (new_bits + bitmap_wordlength - 1) / bitmap_wordlength;
	b->bits = new_bits;
	bitmap_type* new_array = calloc (new_words, sizeof(bitmap_type));
	memcpy (new_array, b->array, sizeof(bitmap_type)*b->words);
	free (b->array);
	b->words = new_words;
	b->array = new_array;
}

inline void bitmap_set(bitmap *b, int n)
{
  int word = n >> bitmap_shift;		// n / bitmap_wordlength
  int position = n & bitmap_mask;	// n % bitmap_wordlength
  if (n > b->bits) { 
	  bitmap_expand (b, n*2);
  }
  b->array[word] |= bitmap_one << position;
}

inline void bitmap_clear(bitmap *b, int n)
{
  if (n > b->bits) {fprintf (stderr, "out of range bitmap_clear.\n"); return;}
  int word = n >> bitmap_shift;         // n / bitmap_wordlength
  int position = n & bitmap_mask;       // n % bitmap_wordlength
  b->array[word] &= ~(bitmap_one << position);
}

inline int  bitmap_read(bitmap *b, int n)
{
  if (n > b->bits) {fprintf (stderr, "out of range bitmap_read.\n"); return 0;}
  int word = n >> bitmap_shift;         // n / bitmap_wordlength
  int position = n & bitmap_mask;       // n % bitmap_wordlength
  return (b->array[word] >> position) & 1;
}

bitmap * bitmap_allocate(int bits)
{
  // error-checking should be better :-)
  bitmap *b = malloc(sizeof(bitmap));
  b->bits = bits;
  b->words = (bits + bitmap_wordlength - 1) / bitmap_wordlength;
    // divide, but round up for the ceiling
  b->array = calloc(b->words, sizeof(bitmap_type));
  return b;
}

void bitmap_deallocate(bitmap *b)
{
  // error-checking should be better :-)
  free(b->array);
  free(b);
}

void bitmap_print(bitmap *b)
{
  int i;
  for (i = 0; i < b->words; i++)
    { printf(" " bitmap_fmt, b->array[i]); }
  printf("\n");
}

