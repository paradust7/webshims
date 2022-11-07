// This code runs on a WebWorker wrapped inside a function body.
// To export a global symbol, assigned it through 'self'.
self.proxyUrl = "";
function setProxy(url) {
    self.proxyUrl = url;
}
self.setProxy = setProxy;

self.vpnCode = "";
function setVPN(code) {
  self.vpnCode = code;
}
self.setVPN = setVPN;

function inet_ntop(n) {
    const a = (n >> 24) & 0xFF;
    const b = (n >> 16) & 0xFF;
    const c = (n >>  8) & 0xFF;
    const d = (n >>  0) & 0xFF;
    return `${a}.${b}.${c}.${d}`;
}
self.inet_ntop = inet_ntop;

function inet_pton(ip) {
    const ret = new ArrayBuffer(4);
    const v = new DataView(ret);
    var [a, b, c, d] = ip.split('.');
    v.setUint8(0, parseInt(a));
    v.setUint8(1, parseInt(b));
    v.setUint8(2, parseInt(c));
    v.setUint8(3, parseInt(d));
    return ret;
}
self.inet_pton = inet_pton;

self.EP_MAGIC = 0x778B4CF3;

function unencapsulate(data) {
    // Data is encapsulated with a 12 byte header.
    // Magic      - 4 bytes EP_MAGIC
    // Dest IP    - 4 bytes 0xAABBCCDD for AA.BB.CC.DD
    // Dest Port  - 2 bytes
    // Packet Len - 2 bytes
    if (!(data instanceof ArrayBuffer)) {
        throw new Error("Received text over encapsulated channel");
    }
    if (data.byteLength < 12) {
        throw new Error("Encapsulated header not present (short message)");
    }
    const view = new DataView(data);
    const magic = view.getUint32(0);
    if (magic != EP_MAGIC) {
        throw new Error("Encapsulated packet header corrupted");
    }
    const src_ip = inet_ntop(view.getUint32(4));
    const src_port = view.getUint16(8);
    const pktlen = view.getUint16(10);
    if (data.byteLength != 12 + pktlen) {
        throw new Error("Invalid encapsulated packet length");
    }
    return [src_ip, src_port, data.slice(12)];
}
self.unencapsulate = unencapsulate;

function encapsulate(dest_ip, dest_port, data) {
    const edata = new ArrayBuffer(12 + data.byteLength);
    const view = new DataView(edata);
    view.setUint32(0, EP_MAGIC);
    (new Uint8Array(edata, 4, 4)).set(new Uint8Array(inet_pton(dest_ip)));
    view.setUint16(8, dest_port);
    view.setUint16(10, data.byteLength);
    (new Uint8Array(edata, 12)).set(data);
    return edata;
}
self.encapsulate = encapsulate;

class ProxyLink {
    constructor(bind_port, udp) {
        this.bind_port = bind_port;
        this.udp = udp;
        this.onopen = null;
        this.onerror = null;
        this.onclose = null;
        this.onmessage = null;
        this.expectHandshake = null;
        this.userEnabled = false;
        this.userBuffer = [];
        this.index = ProxyLink.links.length;
        ProxyLink.links.push(this);
        this.ws = null;
        this.activated = false;
        this.dead = false;
        this.encapsulated = false;
        this.receive_info = null;
        if (this.udp && vpnCode) {
            this.encapsulated = true;
            this._activate();
        }
    }

    connect(ip, port) {
        if (this.udp)
            throw new Error('ProxyLink: connect() called on udp socket');
        this.connect_info = [ip, port];
        this._activate();
    }

    _activate() {
        if (this.activated)
            throw new Error('ProxyLink activated twice');
        this.activated = true;
        const ws = new WebSocket(proxyUrl);
        this.ws = ws;
        ws.binaryType = "arraybuffer";
        ws.onopen = this.handleOpen.bind(this);
        ws.onerror = this.handleError.bind(this);
        ws.onclose = this.handleClose.bind(this);
        ws.onmessage = this.handleMessage.bind(this);
    }

    handleOpen() {
        var req;
        // Send proxy request
        if (this.encapsulated) {
            req = `VPN ${vpnCode} BIND IPV4 UDP ${this.bind_port}`;
            this.expectHandshake = 'BIND OK';
        } else {
            const [ip, port] = this.connect_info;
            req = `PROXY IPV4 ${this.udp ? "UDP" : "TCP"} ${ip} ${port}`;
            this.expectHandshake = 'PROXY OK';
	}
        this.ws.send(req);
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
        try {
            this._handleMessage(e);
        } catch (err) {
            console.log("ProxyLink javascript exception");
            console.log(err);
            this._close();
        }
    }

    _handleMessage(e) {
        const data = e.data;
        if (!this.userEnabled) {
            // Waiting for proxy auth message
            if (!this.expectHandshake) {
                throw new Error("Invalid message before proxy request");
            }
            if (data != this.expectHandshake) {
                throw new Error("Invalid handshake response");
            }
            this._enable();
            this.onopen();
            return;
        }
        if (this.encapsulated) {
            const [src_ip, src_port, rdata] = unencapsulate(data);
            this.onmessage(rdata, src_ip, src_port);
        } else {
            const [src_ip, src_port] = this.connect_info;
            this.onmessage(data, src_ip, src_port);
        }
    }

    sendto(data, ip, port) {
        if (this.dead) return;
        if (!this.activated) {
            this.connect_info = [ip, port];
            this._activate();
        }
        if (this.encapsulated) {
            const edata = encapsulate(ip, port, data);
            this._send(edata);
        } else {
            if (this.connect_info[0] !== ip || this.connect_info[1] !== port) {
                throw new Error('ProxyLink: Address mismatch on non-encapsulated link');
            }
            this._send(data);
        }
    }

    send(data) {
        if (this.dead) return;
        if (!this.activated) {
            throw new Error('ProxyLink: send before connect');
        }
        if (this.encapsulated) {
            throw new Error('ProxyLink: Encapsulated send not supported');
        }
        this._send(data);
    }

    _send(data) {
        if (typeof data !== 'string') {
            // If this copy isn't done, send fails with:
            //   "The provided ArrayBufferView value must not be shared."
            data = new Uint8Array(data);
        }
        if (this.userEnabled) {
            this.ws.send(data);
        } else {
            this.userBuffer.push(data);
        }
    }

    _enable() {
        this.userEnabled = true;
        for (const data of this.userBuffer) {
            this.ws.send(data);
        }
        this.userBuffer = null;
    }

    // Call this internally to dispatch the onclose callback but leave
    // this link on the list.
    _close() {
        this.dead = true;
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
    // invoke onclose(), and immediately removes this link from the list.
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
