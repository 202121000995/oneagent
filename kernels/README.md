# Kernel binaries

Put Linux kernel release files here before building an offline package.

Accepted examples:

- `sing-box-1.13.13-linux-amd64.tar.gz`
- `mihomo-linux-amd64-v1.19.27.gz`

`deploy/package-offline.sh` will extract these files and include `sing-box` and `mihomo` in the offline zip.
