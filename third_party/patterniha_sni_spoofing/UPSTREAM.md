Upstream: https://github.com/patterniha/SNI-Spoofing
Pinned commit: 13b78cf7e073f38d9cadcff542faf4a00b0a6de2
License: GNU GPL v3 (see LICENSE)

The runtime integration in uac_desktop/pattern_core is adapted from this source.
Changes include lifecycle management, graceful WinDivert shutdown, bounded sessions,
large bidirectional relay buffers, socket tuning, traffic counters, route fallback,
and a fix for asyncio.sock_sendall return-value handling that affected file uploads.
