# public_internet_exporter

I wanted to know when (and for how long) public internet disruptions from my ISP happen in my home lab. 
It’s a Prometheus exporter that sends ICMP echo requests to public DNS resolvers (for example, `1.1.1.1` and `8.8.8.8`) and reports whether at least one of them is reachable.

## Metrics

- `public_internet_exporter_up`: `1` if the internet is reachable, otherwise `0`.
- `public_internet_exporter_build_info`: build information (`version`, `commit`, `build_date`).

## Usage

```bash
./public_internet_exporter --web.listen-address=":9100" --web.metrics-path="/metrics" --log.level info
```

Endpoints:

- `/metrics`
- `/healthz`

## Notes

- Sending ICMP requires raw socket permissions (Linux: run as root or grant `CAP_NET_RAW`, e.g. `sudo setcap cap_net_raw=+ep ./public_internet_exporter`).
- The list of IPs to ping is currently hard-coded in `main.go`.
