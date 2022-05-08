self.proxyUrl = "";
function setProxy(url) {
    self.proxyUrl = url;
}
self.setProxy = setProxy;

self.textEncoder = new TextEncoder();
self.textDecoder = new TextDecoder();

class ProxyLink {
    constructor(ip, port, udp) {
        this.ip = ip;
        this.port = port;
        this.udp = udp;
        this.onopen = null;
        this.onerror = null;
        this.onclose = null;
        this.onmessage = null;
        this.sentProxyRequest = false;
        this.userEnabled = false;
        this.userBuffer = [];
        this.index = ProxyLink.links.length;
        ProxyLink.links.push(this);
        const ws = new WebSocket(proxyUrl);
        this.ws = ws;
        ws.binaryType = "arraybuffer";
        ws.onopen = this.handleOpen.bind(this);
        ws.onerror = this.handleError.bind(this);
        ws.onclose = this.handleClose.bind(this);
        ws.onmessage = this.handleMessage.bind(this);
    }

    handleOpen() {
        // Send proxy request
        const req = `PROXY IPV4 ${this.udp ? "UDP" : "TCP"} ${this.ip} ${this.port}`;
        this.ws.send(textEncoder.encode(req));
        this.sentProxyRequest = true;
    }

    handleError() {
        if (this.onerror) {
            this.onerror();
        }
    }

    handleClose() {
        this._close();
    }

    handleMessage(e) {
        if (!this.userEnabled) {
            // Waiting for proxy auth message
            if (!this.sentProxyRequest) {
                console.log("Got invalid message before proxy request");
                this._close();
                return;
            }
            const ok = textDecoder.decode(e.data);
            if (ok != "PROXY OK") {
                console.log("Got invalid proxy message");
                this._close();
                return;
            }
            //console.log("Got proxy OK");
            this._enable();
            this.onopen();
            return;
        }
        //console.log("Relaying message");
        this.onmessage(e.data);
    }

    send(data) {
        //console.log("Got send");
        const ws = this.ws;
        if (!ws) return;
        // If this copy isn't done, send fails with:
        //   "The provided ArrayBufferView value must not be shared."
        data = new Uint8Array(data);
        if (this.userEnabled) {
            //console.log("Sending direct");
            ws.send(data);
        } else {
            //console.log("Sending to userBuffer");
            this.userBuffer.push(data);
        }
    }

    _enable() {
        this.userEnabled = true;
        for (const data of this.userBuffer) {
            //console.log("Flushing from buffer");
            this.ws.send(data);
        }
        this.userBuffer = null;
    }

    // Call this internally. It will dispatch callbacks.
    _close() {
        const ws = this.ws;
        if (ws) {
            ws.onopen = ws.onerror = ws.onclose = ws.onmessage = null;
            ws.close();
            this.ws = null;
        }
        if (this.onclose) {
            this.onclose();
        }
    }

    // This should only be called externally, because it does not
    // invoke callbacks, and removes the index from the list.
    close() {
        this.onopen = null;
        this.onerror = null;
        this.onclose = null;
        this.onmessage = null;
        this._close();
        delete ProxyLink.links[this.index];
    }

    static get(index) {
        return ProxyLink.links[index];
    }
}
self.ProxyLink = ProxyLink;
// minify can't handle inline static members, so declare it here.
self.ProxyLink.links = [null]; // 0 considered an invalid index
