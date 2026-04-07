#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Synthetic ELF that mimics suspicious traits for static analysis only */
static const char *C2_URLS[] = {
    "http://archive.legacy-c2.net/update",
    "http://mirror.old-bot.biz/payload"
};

static const char *C2_IPS[] = {
    "192.0.2.123", // TEST-NET-1
    "198.51.100.42" // TEST-NET-2
};

static const char *UA = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)";

int fake_unpack(unsigned char *buf, size_t len) {
    /* emulate a trivial transform */
    for (size_t i = 0; i < len; ++i) {
        buf[i] ^= 0xA5;
    }
    return 0;
}

int main(void) {
    puts("SIM_ELF_MIMIC: benign synthetic binary");
    puts("C2_URLS: http://archive.legacy-c2.net/update, http://mirror.old-bot.biz/payload");
    puts("C2_IPS: 192.0.2.123, 198.51.100.42");
    puts("User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)");

    unsigned char data[] = {0x10,0x20,0x30,0x40,0x50};
    fake_unpack(data, sizeof(data));

    FILE *f = fopen("sandbox_output/sim_elf_mimic.txt", "w");
    if (f) {
        time_t now = time(NULL);
        fprintf(f, "SIM_ELF_MIMIC artifact time=%ld\n", (long)now);
        fclose(f);
    }

    return 0;
}


