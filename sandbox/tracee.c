#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main() {
    int i;
    int fd = open("output", O_CREAT|O_WRONLY, 0644);

    write(fd, "A", 1);

    return 0;
}
