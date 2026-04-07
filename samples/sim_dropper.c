#include <stdio.h>
#include <stdlib.h>

int main() {
    // Drop a benign text file into sandbox_output/
    system("mkdir -p sandbox_output");
    FILE *f = fopen("sandbox_output/dropped.txt", "w");
    if (!f) {
        perror("open");
        return 1;
    }
    const char *msg = "SIM_DROPPER: benign file created.\n";
    fputs(msg, f);
    fclose(f);
    printf("SIM_DROPPER: done.\n");
    return 0;
}


