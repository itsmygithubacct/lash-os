#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static FILE *services;
static struct servent entry;
static char line[2048], *aliases[64];
void endservent(void) {
    if (services)
        fclose(services);
    services = NULL;
}
void setservent(int stayopen) {
    (void)stayopen;
    if (services)
        rewind(services);
    else
        services = fopen("/etc/services", "r");
}
struct servent *getservent(void) {
    if (!services)
        setservent(0);
    if (!services)
        return NULL;
    while (fgets(line, sizeof(line), services)) {
        char *comment = strchr(line, '#');
        if (comment)
            *comment = 0;
        char *save, *name = strtok_r(line, " \t\r\n", &save),
                    *port = strtok_r(NULL, " \t\r\n", &save);
        if (!name || !port)
            continue;
        char *protocol = strchr(port, '/');
        if (!protocol)
            continue;
        *protocol++ = 0;
        char *end;
        long number = strtol(port, &end, 10);
        if (*end || number < 0 || number > 65535)
            continue;
        entry.s_name = name;
        entry.s_port = htons(number);
        entry.s_proto = protocol;
        entry.s_aliases = aliases;
        size_t count = 0;
        while (count < 63 && (aliases[count] = strtok_r(NULL, " \t\r\n", &save)))
            count++;
        aliases[count] = NULL;
        return &entry;
    }
    return NULL;
}
