/* 
 * Simple tool to decrypt D-LINK DIR-850L REVB firmwares 
 *
 * $ gcc -o revbdec revbdec.c
 * $ ./revbdec DIR850L_REVB_FW207WWb05_h1ke_beta1.bin wrgac25_dlink.2013gui_dir850l > DIR850L_REVB_FW207WWb05_h1ke_beta1.decrypted
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define USAGE "Usage: decimg <filename> <key>\n"

int main(int    argc,
         char   **argv)
{
        int     i, fi;
        int     fo = STDOUT_FILENO, fe = STDERR_FILENO;

        if (argc != 3)
        {
                write(fe, USAGE, strlen(USAGE));
                return (EXIT_FAILURE);
        }

        if ((fi = open(argv[1], O_RDONLY)) == -1)
        {
                perror("open");
                write(fe, USAGE, strlen(USAGE));
                return (EXIT_FAILURE);
        }

        const char *key = argv[2];
        int kl = strlen(key);

        i = 0;
        while (1)
        {
                char buffer[4096];
                int j, len;
                len = read(fi, buffer, 4096);
                if (len <= 0)
                        break;
                for (j = 0; j < len; j++) {
                        buffer[j] ^= (i + j) % 0xFB + 1;
                        buffer[j] ^= key[(i + j) % kl];
                }
                write(fo, buffer, len);
                i += len;
        }

       return (EXIT_SUCCESS);
}
