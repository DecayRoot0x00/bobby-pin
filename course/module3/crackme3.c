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

    printf("BobbinSoft Pro v3 - enterprise build\n");
    printf("Enter license key: ");
    scanf("%63s", key);

    if (djb2(key) == 0x0BADC0DEu) {
        printf("Welcome back, licensed user.\n");
        return 0;
    }
    return 3;
}
