#include <dlfcn.h>
#include <pthread.h>

#include "frida.h"

int GADGET_LOADED = 0;

void bootstrap_gadget() {

    pthread_t tid;
    pthread_create(&tid, NULL, load_library, NULL);

}

void *load_library() {

    void *handle = dlopen("/usr/local/lib/frida-gadget.so", RTLD_LAZY);

    if (handle) {
        dlclose(handle);
    } else {
        GADGET_LOADED = 1;
    }

    return NULL;
}
