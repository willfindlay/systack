#include <unistd.h>
#include <stdio.h>

void do_prints(void) {
    char buf[] = "Hello system call world!\n";
    write(STDOUT_FILENO, buf, sizeof(buf));
    printf("Hello libc world!\n");
}

int main(int argc, char *argv[])
{
    char buf[] = "Hello system call world!\n";
    write(STDOUT_FILENO, buf, sizeof(buf));
    printf("Hello libc world!\n");

    do_prints();

    sleep(1);

    return 0;
}
