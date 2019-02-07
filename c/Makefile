all: 32 64 32-static 64-static

32:
	gcc -m32 -pie -fPIC -fPIE -o main32 main.c

64:
	gcc -pie -fPIC -fPIE -o main64 main.c

32-static:
	gcc -m32 -static -fPIC -fPIE -o main32-static main.c

64-static:
	gcc -static -fPIC -fPIE -o main64-static main.c
