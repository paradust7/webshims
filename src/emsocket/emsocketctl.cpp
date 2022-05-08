/*
MIT License

Copyright (c) 2022 paradust7

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#define EMSOCKET_INTERNAL

#include "emsocketctl.h"
#include <iostream>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <pthread.h>
#include <emscripten.h>
#include "proxyjs.gen.h"

namespace emsocket {
    bool didInit;
    pthread_t ioThread;
    std::mutex ioMutex;
    std::condition_variable ioCv;
    std::vector<std::function<void()> > ioCallbacks;
    uint64_t ioCounter = 0;
}

using namespace emsocket;

static void *io_thread_main(void *);

void emsocket_init(void) {
    if (didInit) return;
    didInit = true;

    // Launch dedicated i/o thread
    int rc = pthread_create(&ioThread, NULL, io_thread_main, NULL);
    if (rc != 0) {
        std::cerr << "emsocket_init: Failed to launch I/O thread" << std::endl;
        abort();
    }
}

EM_JS(void, _set_proxy, (const char *url), {
    setProxy(UTF8ToString(url));
});

void emsocket_set_proxy(const char *url) {
    char *urlcopy = strdup(url);
    emsocket_run_on_io_thread(false, [urlcopy]() {
        _set_proxy(urlcopy);
        free(urlcopy);
    });
}


static void io_thread_reenter(void) {
    std::vector<std::function<void()> > callbacks;
    {
        const std::lock_guard<std::mutex> lock(ioMutex);
        callbacks = std::move(ioCallbacks);
        ioCallbacks.clear();
        ioCounter += 1;
    }
    ioCv.notify_all();
    for (const auto &callback : callbacks) {
        callback();
    }
}

static void *io_thread_main(void *) {
    init_proxyjs();
    // TODO: emsocket_run_on_io_thread should use a WebWorker
    // message to wakeup the I/O thread instead of polling
    // every 10ms.
    emscripten_set_main_loop(io_thread_reenter, 100, EM_TRUE);
    abort(); // unreachable
}

namespace emsocket {

// Returns the id of the callback.
// Use this id in emsocket_remove_io_callback()
void emsocket_run_on_io_thread(bool sync, std::function<void()> && callback) {
    std::unique_lock<std::mutex> lock(ioMutex);
    ioCallbacks.emplace_back(std::move(callback));
    if (sync) {
        // Wait for 2 counter clicks, that'll guarantee the callback has run.
        uint64_t ioTarget = ioCounter + 2;
        ioCv.wait(lock, [&](){ return ioCounter >= ioTarget; });
    }
}

} // namespace emsocket
