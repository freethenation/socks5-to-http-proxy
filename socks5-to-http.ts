#!/usr/bin/env node

import * as tls from 'tls';
import * as net from 'net';
import { Socket } from 'net';
const socks = require('socksv5');
import { URL } from 'url'
import { debuglog } from 'util'
import { ArgumentParser } from "argparse";
const debug = debuglog('socks-to-html');

type AcceptCallback = (intercept: boolean) => Socket | undefined

interface AcceptInfo {
    srcAddr: string,
    srcPort: number,
    dstAddr: string,
    dstPort: number,
}

class HttpError extends Error {
    statusCode: number;
    constructor(message: string, statusCode: number) {
        super(message); // (1)
        this.name = "HttpError"; // (2)
        this.statusCode = statusCode
    }
}

//lifted and tweaked from https://github.com/TooTallNate/node-https-proxy-agent/blob/master/src/parse-proxy-response.ts#L11
async function parseProxyResponse(socket: Socket): Promise<{ statusCode: number, buffered: Buffer }> {
    const debug = debuglog('parse-proxy-response');
    return new Promise((resolve, reject) => {
        // we need to buffer any HTTP traffic that happens with the proxy before we get
        // the CONNECT response, so that if the response is anything other than an "200"
        // response code, then we can re-play the "data" events on the socket once the
        // HTTP parser is hooked up...
        let buffersLength = 0;
        const buffers: Buffer[] = [];
        function read() {
            const b = socket.read();
            if (b) ondata(b);
            else socket.once('readable', read);
        }
        function cleanup() {
            socket.removeListener('end', onend);
            socket.removeListener('error', onerror);
            socket.removeListener('close', onclose);
            socket.removeListener('readable', read);
        }
        function onclose(err: boolean) {
            debug('onclose had error %o', err);
            cleanup()
        }
        function onend() {
            debug('onend');
            cleanup()
        }
        function onerror(err: Error) {
            debug('onerror %o', err);
            cleanup();
            reject(err);
        }
        function ondata(b: Buffer) {
            buffers.push(b);
            buffersLength += b.length;

            const buffered = Buffer.concat(buffers, buffersLength);
            const endOfHeaders = buffered.indexOf('\r\n\r\n');

            if (endOfHeaders === -1) {
                // keep buffering
                debug('have not received end of HTTP headers yet...');
                read();
                return;
            }

            const firstLine = buffered.toString(
                'ascii',
                0,
                buffered.indexOf('\r\n')
            );
            const statusCode = +firstLine.split(' ')[1];
            cleanup()
            debug('got proxy server response: %o', firstLine);
            resolve({
                statusCode,
                buffered
            });
        }
        socket.on('error', onerror);
        socket.on('close', onclose);
        socket.on('end', onend);
        read();
    });
}

async function httpProxyConnect(proxy: URL, destHost: string, destPort: number) {
    //connect
    let conn: Socket
    if (proxy.protocol == "https") {
        conn = tls.connect(parseInt(proxy.port), proxy.hostname, { servername: proxy.hostname })
        await new Promise(resolve => conn.once('secureConnect', resolve))
    } else {
        conn = net.connect(parseInt(proxy.port), proxy.hostname)
        await new Promise(resolve => conn.once('connect', resolve))
    }
    //write http proxy headers
    conn.write([
        `CONNECT ${destHost}:${destPort} HTTP/1.1`,
        `Host: ${destHost}:${destPort}`,
        'Proxy-Connection: Keep-Alive',
        proxy.username ? `Proxy-Authorization: Basic ${Buffer.from(proxy.username + ':' + proxy.password).toString('base64')}` : undefined,
        '',
        ''
    ].filter(i => typeof i !== "undefined").join('\r\n'))
    const proxyResponse = await parseProxyResponse(conn)
    if (proxyResponse.statusCode != 200) {
        console.error(`Error sending CONNECT http method to http proxy`, { statusCode: proxyResponse.statusCode, buffer: proxyResponse.buffered.toString(), destHost, destPort })
        throw new HttpError(`Error sending CONNECT http method to http proxy`, proxyResponse.statusCode)
    }
    return conn

}

class SocksToHttpProxyHandler {
    proxySocket: Socket | undefined;
    socksSocket: Socket | undefined;
    isDestroyed: boolean = false;
    proxyUrl: URL;
    constructor(proxyUrl: string, public info: AcceptInfo, private accept: AcceptCallback, private deny: () => undefined) {
        this.proxyUrl = new URL(proxyUrl)
        this.onSocksSocketClose = this.onSocksSocketClose.bind(this)
        this.onSocksSocketError = this.onSocksSocketError.bind(this)
        this.onProxySocketClose = this.onProxySocketClose.bind(this)
        this.onProxySocketError = this.onProxySocketError.bind(this)
    }
    async init() {
        debug(`opening for destination ${this.info.dstAddr}:${this.info.dstPort}`)
        try {
            this.proxySocket = await httpProxyConnect(this.proxyUrl, this.info.dstAddr, this.info.dstPort)
            this.socksSocket = this.accept(true)
        } catch (error) {
            if (error instanceof HttpError && error.statusCode == 502) {
                this.socksSocket = this.accept(true)
                this.socksSocket?.end(Buffer.from([0x05, 0x04])) // 0x04=Network unreachable see https://datatracker.ietf.org/doc/html/rfc1928
                return;
            } else {
                throw error
            }
        }
        if (!this.socksSocket) {
            //looked at the code and accept can return undefined. Didn't look any further.
            //https://github.com/mscdex/socksv5/blob/master/lib/server.js#L106
            console.warn(`undefined socks proxy ${this.info.dstAddr}:${this.info.dstPort}`)
            this.proxySocket.destroy()
            this.isDestroyed = true;
            return;
        }
        this.socksSocket.pipe(this.proxySocket)
        this.proxySocket.pipe(this.socksSocket)
        this.socksSocket.once('close', this.onSocksSocketClose)
        this.proxySocket.once('close', this.onProxySocketClose)
        this.proxySocket.once('error', this.onSocksSocketError)
        this.socksSocket.once('error', this.onProxySocketError)
    }
    destroy() {
        if (this.isDestroyed) return;
        this.isDestroyed = true;
        this.socksSocket?.destroy()
        this.proxySocket?.destroy()
        this.socksSocket?.off('close', this.onSocksSocketClose)
        this.proxySocket?.off('close', this.onProxySocketClose)
        this.proxySocket?.off('error', this.onSocksSocketError)
        this.socksSocket?.off('error', this.onProxySocketError)
    }
    private onSocksSocketClose() {
        debug(`close on socks socket destination ${this.info.dstAddr}:${this.info.dstPort}`)
        this.destroy()
    }
    private onProxySocketClose() {
        debug(`close on proxy socket destination ${this.info.dstAddr}:${this.info.dstPort}`)
        this.destroy()
    }
    private onSocksSocketError(error: Error) {
        console.error(`error on socks socket destination ${this.info.dstAddr}:${this.info.dstPort} error ${error}`)
        this.destroy()
    }
    private onProxySocketError(error: Error) {
        console.error(`error on proxy socket destination ${this.info.dstAddr}:${this.info.dstPort} error ${error}`)
        this.destroy()
    }
}


interface CliArgs {
    proxy: string,
    port: number,
    interface: string,
}

function parseArgs() {
    const parser = new ArgumentParser({
        add_help: true,
        description: 'Exposes a local socks proxy that forwards to a remote http proxy. Supports mozilla private network.',
    })
    parser.add_argument('--proxy', { action: 'store', required: true, help: 'Specify remote http proxy to connect to. E.g. https://user:PASSWORD@somehost.com:2486' })
    parser.add_argument('--port', { action: 'store', type: 'int', default: 1080, help: 'Port to host socks server on. Defaults to port 1080.' })
    parser.add_argument('--interface', { action: 'store', default: '127.0.0.1', help: 'Interface to bind socks server to. Defaults to 127.0.0.1.' })
    return parser.parse_args() as CliArgs
}

function main(args: CliArgs) {
    //add a uncaughtException so node does not crash
    process.on('uncaughtException', function (err) {
        console.error("uncaughtException", err.stack);
    });
    var srv = socks.createServer(async function (info: AcceptInfo, accept: AcceptCallback, deny: () => undefined) {
        debug(`opening for destination ${info.dstAddr}:${info.dstPort}`)
        const handler = new SocksToHttpProxyHandler(args.proxy, info, accept, deny)
        await handler.init()
    });
    srv.listen(args.port, args.interface, function () {
        console.info(`SOCKS server listening on ${args.interface}:${args.port}`);
    });
    srv.useAuth(socks.auth.None());
}

if (require.main === module) {
    main(parseArgs())
}
