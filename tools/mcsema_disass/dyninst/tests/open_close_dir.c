#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <errno.h>

int main (int argc, char **argv)
{
    if (argc != 2)
    {
        puts ("error: need exactly one argument");
        return 1;
    }

    DIR *dir = opendir (argv [1]);
    if (!dir)
        perror ("opendir");
    else
        closedir (dir);

    printf ("errno: %d\n", errno);

    return 0;
}
