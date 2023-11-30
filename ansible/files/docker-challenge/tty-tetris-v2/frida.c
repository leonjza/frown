#include <dlfcn.h>
#include <pthread.h>

#include "frida.h"

int load_frida_gadget() {
    pthread_t tid;
    char *lib = "/usr/local/lib/frida-gadget.so";

    int r = pthread_create(&tid, NULL, load_library, lib);
    if (r > 0) return r;

    return pthread_detach(tid);
}

void *load_library(void *libPath) {
    void *handle = dlopen((char *) libPath, RTLD_LAZY);

    if (handle) dlclose(handle);

    return NULL;
}
