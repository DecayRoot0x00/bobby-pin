#include <stdio.h>
#include <string.h>

static unsigned int djb2(const char *s) {
    unsigned int h = 5381u;
    while (*s) {
        h = h * 33u + (unsigned char)*s;
        s++;
    }
    return h;
}

static int account_active(const char *key) {
    size_t n = strlen(key);
    return n >= 8u && (unsigned char)key[0] != 'X';
}

int main(void) {
    char key[64];

    printf("BobbinSoft Pro v2 - activation\n");
    printf("Enter license key: ");
    scanf("%63s", key);

    if (djb2(key) == 0x0BADC0DEu) {
        if (account_active(key)) {
            printf("Access granted. Welcome back!\n");
            return 0;
        }
        printf("Account suspended. Contact support.\n");
        return 2;
    }
    printf("License invalid. Please purchase a key.\n");
    return 1;
}
