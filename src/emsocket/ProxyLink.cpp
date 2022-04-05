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

#include <iostream>
#include <string>
#include <cassert>
#include <cstdint>
#include <memory.h>
#include <emscripten/websocket.h>
#include "VirtualSocket.h"
#include "ProxyLink.h"
#include "emsocketctl.h"

extern "C" {
    // Callbacks to re-enter C/C++ from javascript
    EMSCRIPTEN_KEEPALIVE
    void proxylink_onopen(void *thisPtr);
    EMSCRIPTEN_KEEPALIVE
    void proxylink_onerror(void *thisPtr);
    EMSCRIPTEN_KEEPALIVE
    void proxylink_onclose(void *thisPtr);
    EMSCRIPTEN_KEEPALIVE
    void proxylink_onmessage(void *thisPtr, const void *buf, size_t n);
}

EM_JS(int, setup_proxylink_websocket, (const char* url, void *thisPtr), {
    if (!self.hasOwnProperty('mywebsockets')) {
        self.mywebsockets = [null];
        self.w_proxylink_onopen = Module.cwrap('proxylink_onopen', null, ['number']);
        self.w_proxylink_onerror = Module.cwrap('proxylink_onerror', null, ['number']);
        self.w_proxylink_onclose = Module.cwrap('proxylink_onclose', null, ['number']);
        self.w_proxylink_onmessage = Module.cwrap('proxylink_onmessage', null, ['number', 'number', 'number']);
    }

    const ws = new WebSocket(UTF8ToString(url));
    const index = mywebsockets.length;
    mywebsockets.push(ws);
    ws.binaryType = "arraybuffer";
    ws.onopen = (e) => {
        w_proxylink_onopen(thisPtr);
    };
    ws.onerror = (e) => {
        w_proxylink_onerror(thisPtr);
    };
    ws.onclose = (e) => {
        w_proxylink_onclose(thisPtr);
    };
    ws.onmessage = (e) => {
        var len = e.data.byteLength;
        var buf = _malloc(len);
        HEAPU8.set(new Uint8Array(e.data), buf);
        w_proxylink_onmessage(thisPtr, buf, len);
        _free(buf);
    };

    return index;
});

EM_JS(void, send_proxylink_websocket, (int index, const void *data, int len), {
    const ws = mywebsockets[index];
    if (ws) {
        ws.send(new Uint8Array(HEAPU8.subarray(data, data + len)));
    }
});

EM_JS(void, delete_proxylink_websocket, (int index), {
    const ws = mywebsockets[index];
    if (ws) {
        delete mywebsockets[index];
        ws.onopen = ws.onerror = ws.onclose = ws.onmessage = null;
        ws.close();
    }
});

static void* memdup(const void *data, size_t len) {
    void* buf = malloc(len);
    memcpy(buf, data, len);
    return buf;
}

namespace emsocket {

class ProxyLink : public Link {
public:
    ProxyLink() = delete;
    ProxyLink(const ProxyLink &) = delete;
    ProxyLink& operator=(const ProxyLink &) = delete;

    ProxyLink(VirtualSocket *vs_, const std::string &proxyUrl, const SocketAddr &addr_, bool udp_)
        : wsIndex(-1),
          vs(vs_),
          addr(addr_),
          udp(udp_),
          sentProxyRequest(false),
          receivedProxyAuth(false)
    {

        //std::cerr << "Initialized proxy websocket" << std::endl;
        emsocket_run_on_io_thread(true, [this, proxyUrl]() {
            wsIndex = setup_proxylink_websocket(proxyUrl.c_str(), this);
        });
        assert(wsIndex > 0);
    }

    virtual ~ProxyLink() {
        emsocket_run_on_io_thread(true, [this]() {
            hangup();
        });
    }

    // Called from external thread
    virtual void send(const void *data, size_t len) {
        // This can be called from another thread. Move it to the I/O thread.
        int wsIndex_ = wsIndex;
        void *dataCopy = memdup(data, len);
        emsocket_run_on_io_thread(false, [wsIndex_, dataCopy, len]() {
            send_proxylink_websocket(wsIndex_, dataCopy, len);
            free(dataCopy);
        });
    }

public:

    // Called from I/O thread
    void onopen() {
        // Send a proxy request
        char buf[128];
        sprintf(buf, "PROXY IPV4 %s %s %u", (udp ? "UDP" : "TCP"), addr.getIP().c_str(), addr.getPort());
        send_proxylink_websocket(wsIndex, buf, strlen(buf));
        //std::cerr << "Sent websocket PROXY handshake" << std::endl;
        sentProxyRequest = true;
    }

    // Called from I/O thread
    void onerror() {
        //std::cerr << "ProxyLink got websocket error" << std::endl;
        hangup();
    }

    // Called from I/O thread
    void onclose() {
        //std::cerr << "ProxyLink got websocket close" << std::endl;
        hangup();
    }

    // Called from I/O thread
    void onmessage(const void *buf, int n) {
        if (!sentProxyRequest) {
            //std::cerr << "ProxyLink got invalid message before proxy request" << std::endl;
            hangup();
            return;
        }
        if (!receivedProxyAuth) {
            // Check for proxy auth
            if (n > 16) {
                //std::cerr << "ProxyLink unexpected auth message length (" << n << ")" << std::endl;
                hangup();
                return;
            }
            std::string response((const char*)buf, n);
            if (response == "PROXY OK") {
                receivedProxyAuth = true;
                vs->linkConnected();
                return;
            }
            //std::cerr << "ProxyLink received bad auth: '" << response << "' of length " << n << std::endl;
            hangup();
            return;
        }
        // Regular message
        vs->linkReceived(addr, buf, n);
    }

    // Called from I/O thread
    void hangup() {
        delete_proxylink_websocket(wsIndex);
        vs->linkShutdown();
    }
private:
    // vs is protected by vs_mutex
    VirtualSocket *vs;
    SocketAddr addr;
    bool udp;
    int wsIndex;
    //EMSCRIPTEN_WEBSOCKET_T ws;
    bool sentProxyRequest;
    bool receivedProxyAuth;
};

Link* make_proxy_link(VirtualSocket* vs, const std::string &proxyUrl, const SocketAddr &addr, bool udp) {
    return new ProxyLink(vs, proxyUrl, addr, udp);
}

} // namespace

using namespace emsocket;

EMSCRIPTEN_KEEPALIVE
void proxylink_onopen(void *thisPtr) {
    return reinterpret_cast<ProxyLink*>(thisPtr)->onopen();
}

EMSCRIPTEN_KEEPALIVE
void proxylink_onerror(void *thisPtr) {
    return reinterpret_cast<ProxyLink*>(thisPtr)->onerror();
}

EMSCRIPTEN_KEEPALIVE
void proxylink_onclose(void *thisPtr) {
    return reinterpret_cast<ProxyLink*>(thisPtr)->onclose();
}

EMSCRIPTEN_KEEPALIVE
void proxylink_onmessage(void *thisPtr, const void *buf, size_t n) {
    return reinterpret_cast<ProxyLink*>(thisPtr)->onmessage(buf, n);
}
