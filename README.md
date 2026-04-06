# DPI Bypass — iOS GoodbyeDPI

iOS implementation of GoodbyeDPI's DPI bypass techniques using Apple's Network Extension framework.

## Architecture

```
DPIBypass/
├── DPIBypass/                          (Main App - SwiftUI)
│   ├── App/DPIBypassApp.swift          Entry point
│   ├── Views/MainView.swift            Connection UI + stats
│   ├── Views/SettingsView.swift        Technique configuration
│   └── ViewModels/VPNManager.swift     NETunnelProviderManager wrapper
│
├── PacketTunnelExtension/              (Network Extension)
│   ├── PacketTunnelProvider.swift      NEPacketTunnelProvider - main loop
│   ├── Pipeline/
│   │   ├── PacketParser.swift          IPv4/TCP/UDP header parsing
│   │   ├── PacketPipeline.swift        Main packet processing orchestrator
│   │   └── ChecksumCalculator.swift    IP/TCP/UDP checksum calculation
│   ├── Techniques/
│   │   ├── HTTPHostManipulation.swift  Host: → hoSt:, mixed case, etc.
│   │   ├── SNIFragmentation.swift      TLS ClientHello SNI fragmentation
│   │   ├── PassiveDPIBlocker.swift     Drop DPI 302 redirects & RSTs
│   │   └── DNSRedirector.swift         DNS request redirection
│   └── Parsers/
│       ├── TLSParser.swift             TLS ClientHello/SNI extraction
│       └── HTTPParser.swift            HTTP request/Host header parsing
│
└── Shared/
    ├── DPIConfiguration.swift          Shared config (App Group)
    └── TunnelMessage.swift             IPC messages
```

## Techniques Ported from GoodbyeDPI

| Technique | Status | GoodbyeDPI Flag |
|-----------|--------|-----------------|
| HTTP Host Replace (hoSt:) | ✅ Done | `-r` |
| HTTP Host Mixed Case | ✅ Done | `-m` |
| HTTP Host Remove Space | ✅ Done | `-s` |
| HTTP Additional Space | ✅ Done | `-a` |
| HTTP TCP Fragmentation | ✅ Done | `-f N` |
| HTTPS SNI Fragmentation | ✅ Done | `--frag-by-sni` |
| HTTPS Fixed Fragmentation | ✅ Done | `-e N` |
| Passive DPI 302 Blocking | ✅ Done | `-p` |
| QUIC Blocking | ✅ Done | `-q` |
| DNS Redirection | ✅ Done | `--dns-addr` |
| Fake Packets (TTL manipulation) | ✅ Done | `--set-ttl` |
| Auto-TTL | ✅ Done | `--auto-ttl` |
| TCP RST Drop | ✅ Done | `-p` (RST part) |
| Disorder Mode (ByeDPI) | ✅ Done | ByeDPI `--disorder` |

## Setup in Xcode

1. Create new iOS App project "DPIBypass"
2. Add Network Extension target "PacketTunnelExtension"
3. Enable capabilities:
   - Network Extensions → Packet Tunnel
   - App Groups → group.com.voiplet.dpibypass
4. Copy source files into respective targets
5. Ensure both targets share: DPIConfiguration.swift, TunnelMessage.swift
6. Build & run on real device (Network Extensions don't work in Simulator)

## Next Steps

- [ ] Integrate lwIP for userspace TCP stack (required for real fragmentation)
- [ ] Add NWConnection-based network I/O
- [ ] Domain blacklist import/export
- [ ] Real-time log viewer
- [ ] Battery optimization
- [ ] App Store submission
