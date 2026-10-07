#include <stdio.h>
void c(){ printf("在c里\n"); }
void b(){ c(); }
void a(){ b(); }
int main(){ a(); printf("回main了\n"); return 0; }
