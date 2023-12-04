#include <dlfcn.h>

#include "frida.h"

int load_frida_gadget() {
    return load_library("libgadget.so");
}

int load_library(char *libPath) {
    void *handle = dlopen(libPath, RTLD_LAZY);
    if (!handle) return 1;

    return 0;
}
