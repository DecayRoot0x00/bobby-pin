#include <stdio.h>

static unsigned int djb2(const char *s) {
    unsigned int h = 5381u;
    while (*s) {
        h = h * 33u + (unsigned char)*s;
        s++;
    }
    return h;
}

int main(void) {
    char key[64];

    printf("BobbinSoft Pro - license check\n");
    printf("Enter license key: ");
    scanf("%63s", key);

    if (djb2(key) == 0x0BADC0DEu) {
        printf("Access granted. Thank you for registering!\n");
        return 0;
    }
    printf("License invalid. Please purchase a key.\n");
    return 1;
}
