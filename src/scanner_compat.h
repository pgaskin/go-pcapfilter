#include <stdio.h>

#define EINTR 4
#define EOF (-1)

int fgetc(FILE*);
int getc(FILE*);
int ferror(FILE*);
void clearerr(FILE*);
char* fgets(char* restrict, int, FILE* restrict);
