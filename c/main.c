#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


int main(int argc, char **argv) {
   char buf[1024];
   int fd = open("/etc/profile", O_RDONLY);
   int i = read(fd, buf, 1024);
   buf[i]=0;

   puts(buf);
   printf("hello %s %d\n", argv[1], argc);
   sleep(100);
}
