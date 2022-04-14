# Socks Proxy to Http Proxy

This repo contains a small command line tool which will expose a socks5 proxy locally forwarding its traffic to a remote HTTP proxy or [Firefox Private Network](https://fpn.firefox.com/).

## Usage

```bash
npm install
npm run build
./socks5-to-http --help # Show cli options
./socks5-to-http # To just run with firefox private network
NODE_DEBUG=socks-to-html ./socks5-to-http # Run with debug logging enabled
```
