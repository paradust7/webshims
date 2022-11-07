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
#include <mutex>
#include <memory.h>
#include <emscripten/websocket.h>
#include "VirtualSocket.h"
#include "Packet.h"
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
    void proxylink_onmessage(void *thisPtr, const void *buf, size_t n, const char *ip, uint16_t port);
}

EM_JS(int, proxylink_new, (uint16_t bind_port, bool udp, void *thisPtr), {
    if (!self.hasOwnProperty('w_proxylink_onopen')) {
        self.w_proxylink_onopen = Module.cwrap('proxylink_onopen', null, ['number']);
        self.w_proxylink_onerror = Module.cwrap('proxylink_onerror', null, ['number']);
        self.w_proxylink_onclose = Module.cwrap('proxylink_onclose', null, ['number']);
        self.w_proxylink_onmessage = Module.cwrap('proxylink_onmessage', null, ['number', 'number', 'number', 'number', 'number']);
    }

    const link = new ProxyLink(bind_port, udp);
    link.onopen = () => { w_proxylink_onopen(thisPtr); };
    link.onerror = () => { w_proxylink_onerror(thisPtr); };
    link.onclose = () => { w_proxylink_onclose(thisPtr); };
    link.onmessage = (data, ip, port) => {
        var len = data.byteLength;
        // TODO: Get rid of these allocations
        var buf = _malloc(len);
        HEAPU8.set(new Uint8Array(data), buf);
        var ip_length = lengthBytesUTF8(ip) + 1;
        var ip_buf = _malloc(ip_length);
        stringToUTF8(ip, ip_buf, ip_length);
        w_proxylink_onmessage(thisPtr, buf, len, ip_buf, port);
        _free(buf);
        _free(ip_buf);
    };
    return link.index;
});

EM_JS(void, proxylink_connect, (int index, const char* ip, uint16_t port), {
    const link = ProxyLink.get(index);
    if (link) {
        link.connect(UTF8ToString(ip), port);
    }
});

EM_JS(void, proxylink_sendto, (int index, const void *data, int len, const char *dest_ip, uint16_t dest_port), {
    const link = ProxyLink.get(index);
    if (link) {
        link.sendto(HEAPU8.subarray(data, data + len), UTF8ToString(dest_ip), dest_port);
    }
});


EM_JS(void, proxylink_send, (int index, const void *data, int len), {
    const link = ProxyLink.get(index);
    if (link) {
        link.send(HEAPU8.subarray(data, data + len));
    }
});

EM_JS(void, proxylink_close, (int index), {
    const link = ProxyLink.get(index);
    if (link) {
        link.close();
    }
});

namespace emsocket {

/*
 * Wrapper around the javascript class of the same name
 */
class ProxyLink : public Link {
public:
    ProxyLink() = delete;
    ProxyLink(const ProxyLink &) = delete;
    ProxyLink& operator=(const ProxyLink &) = delete;

    ProxyLink(VirtualSocket *vs_, uint16_t bind_port_, bool udp_)
        : vs(vs_),
          bind_port(bind_port_),
          udp(udp_),
          wsIndex(-1)
    {
        emsocket_run_on_io_thread(true, [this]() {
            wsIndex = proxylink_new(bind_port, udp, this);
        });
        assert(wsIndex > 0);
    }

    virtual ~ProxyLink() {
        emsocket_run_on_io_thread(true, [this]() {
            hangup();
        });
    }

    // Called from external thread
    virtual void connect(const SocketAddr &addr) {
        // Move to I/O thread.
        int wsIndex_ = wsIndex;
        emsocket_run_on_io_thread(false, [wsIndex_, addr]() {
            proxylink_connect(wsIndex_, addr.getIP().c_str(), addr.getPort());
        });
    }

    // Called from external thread
    virtual void sendto(const void *data, size_t len, const SocketAddr &addr) {
        // Move to I/O thread.
        int wsIndex_ = wsIndex;
        Packet *pkt = new Packet(SocketAddr(), data, len);
        emsocket_run_on_io_thread(false, [wsIndex_, pkt, addr]() {
            proxylink_sendto(wsIndex_, &pkt->data[0], pkt->data.size(), addr.getIP().c_str(), addr.getPort());
            delete pkt;
        });
    }

    // Called from external thread
    virtual void send(const void *data, size_t len) {
        // Move to I/O thread.
        int wsIndex_ = wsIndex;
        Packet *pkt = new Packet(SocketAddr(), data, len);
        emsocket_run_on_io_thread(false, [wsIndex_, pkt]() {
            proxylink_send(wsIndex_, &pkt->data[0], pkt->data.size());
            delete pkt;
        });
    }

public:

    // Called from I/O thread
    void onopen() {
	vs->linkConnected();
    }

    // Called from I/O thread
    void onerror() {
        hangup();
    }

    // Called from I/O thread
    void onclose() {
        hangup();
    }

    // Called from I/O thread
    void onmessage(const void *buf, int n, const char *ip, uint16_t port) {
        SocketAddr addr(ip, port);
        vs->linkReceived(addr, buf, n);
    }

    // Called from I/O thread
    void hangup() {
        proxylink_close(wsIndex);
        vs->linkShutdown();
    }
private:
    VirtualSocket *vs;
    uint16_t bind_port;
    bool udp;
    int wsIndex;
};

Link* make_proxy_link(VirtualSocket* vs, uint16_t bindport, bool udp) {
    return new ProxyLink(vs, bindport, udp);
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
void proxylink_onmessage(void *thisPtr, const void *buf, size_t n, const char *ip, uint16_t port) {
    return reinterpret_cast<ProxyLink*>(thisPtr)->onmessage(buf, n, ip, port);
}
