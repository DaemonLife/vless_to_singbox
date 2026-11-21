#!/usr/bin/env python3
"""Convert VLESS links from a text file into sing-box JSON configurations."""

import argparse
import ipaddress
import json
import os
import re
import sys
import tempfile
import unicodedata
import uuid as uuidlib
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit


SUPPORTED_SECURITY = {"none", "tls", "reality"}
SUPPORTED_TRANSPORTS = {
    "tcp",
    "raw",
    "ws",
    "grpc",
    "httpupgrade",
    "http",
    "h2",
}
TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}


def parse_bool(value: str, parameter: str) -> bool:
    """Parse a boolean value commonly used in VLESS query parameters."""
    normalized = value.strip().casefold()

    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False

    raise ValueError(f"Invalid value for {parameter}: {value!r}")


def normalize_server(server: str) -> str:
    """Validate and normalize an IPv4, IPv6, or DNS server address."""
    if not server or any(char.isspace() for char in server):
        raise ValueError("Invalid server address")

    try:
        return str(ipaddress.ip_address(server))
    except ValueError:
        pass

    try:
        ascii_server = server.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("Invalid server domain name") from error

    # A trailing dot is valid in a fully qualified domain name.
    domain = ascii_server[:-1] if ascii_server.endswith(".") else ascii_server
    if not domain or len(domain) > 253:
        raise ValueError("Invalid server domain name")

    labels = domain.split(".")
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if any(not label_pattern.fullmatch(label) for label in labels):
        raise ValueError("Invalid server domain name")

    return ascii_server


def reject_control_characters(value: str, parameter: str) -> str:
    """Reject control characters in values copied into the sing-box config."""
    if any(unicodedata.category(char) == "Cc" for char in value):
        raise ValueError(f"Parameter {parameter} contains control characters")
    return value


def safe_profile_name(fragment: str, index: int) -> str:
    """Decode a profile name and remove terminal/control characters."""
    try:
        decoded = unquote(fragment, errors="strict").strip()
    except UnicodeError:
        decoded = ""

    # Remove control and formatting characters to keep console output clean.
    cleaned = "".join(
        char
        for char in decoded
        if unicodedata.category(char) not in {"Cc", "Cf"}
    ).strip()

    return cleaned[:128] or f"VLESS {index}"


def parse_link(link: str, index: int) -> dict:
    """Parse one VLESS URI and convert it into a sing-box VLESS outbound."""
    try:
        uri = urlsplit(link.strip())
    except ValueError as error:
        raise ValueError(f"Invalid link: {error}") from error

    if uri.scheme.casefold() != "vless":
        raise ValueError("This is not a VLESS link")

    if uri.username is None:
        raise ValueError("The link is missing a UUID")
    if uri.password is not None:
        raise ValueError("The user-info password format is not supported")

    try:
        server = normalize_server(uri.hostname or "")
        port = uri.port
    except ValueError as error:
        raise ValueError(f"Invalid server or port: {error}") from error

    if port is None or not 1 <= port <= 65535:
        raise ValueError("Port must be in the range 1–65535")

    try:
        user_id = str(uuidlib.UUID(unquote(uri.username, errors="strict")))
    except (ValueError, UnicodeError, AttributeError) as error:
        raise ValueError("Invalid VLESS UUID") from error

    try:
        raw_params = parse_qs(
            uri.query,
            keep_blank_values=True,
            encoding="utf-8",
            errors="strict",
        )
    except (ValueError, UnicodeError) as error:
        raise ValueError(f"Invalid query string: {error}") from error

    # Query parameter names are case-insensitive; the last duplicate value wins.
    params = {
        key.casefold(): values[-1]
        for key, values in raw_params.items()
        if values
    }

    def get(*keys: str, default: str = "") -> str:
        for key in keys:
            value = params.get(key.casefold())
            if value is not None and value != "":
                return value
        return default

    security = (get("security", default="none") or "none").strip().casefold()
    transport = (get("type", default="tcp") or "tcp").strip().casefold()
    flow = get("flow").strip().casefold()
    encryption = (get("encryption", default="none") or "none").strip().casefold()

    if encryption not in {"", "none"}:
        raise ValueError(f"Unsupported VLESS encryption: {encryption}")

    if security not in SUPPORTED_SECURITY:
        raise ValueError(f"Unsupported security setting: {security}")

    if transport not in SUPPORTED_TRANSPORTS:
        raise ValueError(f"Unsupported transport: {transport}")

    if transport == "raw":
        transport = "tcp"

    if flow and flow != "xtls-rprx-vision":
        raise ValueError(f"Unsupported flow: {flow}")

    if flow and (security not in {"tls", "reality"} or transport != "tcp"):
        raise ValueError(
            "xtls-rprx-vision requires security=tls/reality and transport=tcp"
        )

    name = safe_profile_name(uri.fragment, index)
    tag = f"proxy-{index}"

    outbound = {
        "type": "vless",
        "tag": tag,
        "server": server,
        "server_port": port,
        "uuid": user_id,
    }

    if flow:
        outbound["flow"] = flow

    # TLS / REALITY settings.
    if security in {"tls", "reality"}:
        server_name = get("sni", "servername", default=server) or server
        reject_control_characters(server_name, "sni")
        if any(char.isspace() for char in server_name):
            raise ValueError("The sni parameter must not contain whitespace")
        tls = {
            "enabled": True,
            "server_name": server_name,
        }

        insecure_value = get("allowinsecure", "insecure")
        if insecure_value != "":
            tls["insecure"] = parse_bool(insecure_value, "allowInsecure")

        fingerprint = get("fp", "fingerprint").strip()
        reject_control_characters(fingerprint, "fp")
        if fingerprint:
            tls["utls"] = {
                "enabled": True,
                "fingerprint": fingerprint,
            }

        alpn_value = get("alpn")
        reject_control_characters(alpn_value, "alpn")
        if alpn_value:
            alpn = [item.strip() for item in alpn_value.split(",") if item.strip()]
            if alpn:
                tls["alpn"] = alpn

        if security == "reality":
            public_key = get("pbk", "publickey").strip()
            reject_control_characters(public_key, "pbk")
            if not public_key:
                raise ValueError("REALITY: missing pbk (public key)")

            reality = {
                "enabled": True,
                "public_key": public_key,
            }

            short_id = get("sid", "shortid").strip()
            if short_id:
                if len(short_id) > 16 or len(short_id) % 2 or not re.fullmatch(
                    r"[0-9a-fA-F]+", short_id
                ):
                    raise ValueError(
                        "REALITY short ID must contain up to 16 hexadecimal characters"
                    )
                reality["short_id"] = short_id.lower()

            tls["reality"] = reality

        outbound["tls"] = tls

    # V2Ray transport settings.
    path = get("path", default="/") or "/"
    reject_control_characters(path, "path")
    host = get("host", "authority").strip()
    reject_control_characters(host, "host")
    if any(char.isspace() for char in host):
        raise ValueError("The host parameter must not contain whitespace")

    if transport == "ws":
        ws_transport = {
            "type": "ws",
            "path": path,
        }

        if host:
            ws_transport["headers"] = {"Host": host}

        early_data = get("ed").strip()
        if early_data:
            try:
                early_data_size = int(early_data)
            except ValueError as error:
                raise ValueError(f"Invalid WebSocket ed value: {early_data!r}") from error
            if not 0 <= early_data_size <= 2_147_483_647:
                raise ValueError("WebSocket ed must be a non-negative integer")
            if early_data_size:
                ws_transport["max_early_data"] = early_data_size

        early_data_header = get("eh").strip()
        if early_data_header:
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", early_data_header):
                raise ValueError("Invalid HTTP header name in the eh parameter")
            ws_transport["early_data_header_name"] = early_data_header

        outbound["transport"] = ws_transport

    elif transport == "grpc":
        grpc_transport = {"type": "grpc"}
        service_name = get("servicename", "service_name").strip()
        reject_control_characters(service_name, "serviceName")
        if service_name:
            grpc_transport["service_name"] = service_name
        outbound["transport"] = grpc_transport

    elif transport == "httpupgrade":
        upgrade_transport = {
            "type": "httpupgrade",
            "path": path,
        }
        if host:
            upgrade_transport["host"] = host
        outbound["transport"] = upgrade_transport

    elif transport in {"http", "h2"}:
        http_transport = {
            "type": "http",
            "path": path,
        }
        if host:
            http_transport["host"] = [host]
        outbound["transport"] = http_transport

    elif transport == "tcp":
        header_type = get("headertype", default="none").strip().casefold()
        if header_type not in {"", "none"}:
            raise ValueError(
                f"TCP headerType={header_type} is not supported"
            )

    return {
        "tag": tag,
        "name": name,
        "outbound": outbound,
    }


def validate_proxy_host(value: str) -> str:
    """Accept loopback addresses only to avoid exposing an unauthenticated proxy."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "Specify a loopback IP address: 127.0.0.1 or ::1"
        ) from error

    if not address.is_loopback:
        raise argparse.ArgumentTypeError(
            "The local proxy can only bind to a loopback address"
        )

    return str(address)


def validate_tun_name(value: str) -> str:
    """Validate a Linux network interface name (maximum 15 characters)."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", value):
        raise argparse.ArgumentTypeError(
            "The TUN interface name must be 1–15 characters long and contain only letters, digits, _, . or -"
        )
    return value


def build_configs(proxies: list[dict], args: argparse.Namespace) -> dict[str, dict]:
    """Build the local-proxy and TUN configurations."""
    proxy_tags = [proxy["tag"] for proxy in proxies]
    outbounds = [proxy["outbound"] for proxy in proxies]

    # Add automatic latency-based server selection unless explicitly disabled.
    if args.no_urltest:
        selector_outbounds = proxy_tags
        default_outbound = proxy_tags[0]
    else:
        outbounds.append(
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": proxy_tags,
                "url": "https://www.gstatic.com/generate_204",
                "interval": "3m",
                "tolerance": 50,
            }
        )
        selector_outbounds = ["auto", *proxy_tags]
        default_outbound = "auto"

    # Keep one selector as the common outbound for DNS and routed traffic.
    outbounds.extend(
        [
            {
                "type": "selector",
                "tag": "proxy",
                "outbounds": selector_outbounds,
                "default": default_outbound,
            },
            {
                "type": "direct",
                "tag": "direct",
            },
        ]
    )

    # Common settings shared by both configurations.
    common = {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {
                    "type": "udp",
                    "tag": "dns-remote",
                    "server": "1.1.1.1",
                    "detour": "proxy",
                }
            ],
            "final": "dns-remote",
            "strategy": "prefer_ipv4",
        },
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": True,
            "final": "proxy",
        },
    }

    # Configuration #1: local SOCKS/HTTP proxy only.
    proxy_config = {
        **common,
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": args.proxy_host,
                "listen_port": args.proxy_port,
            }
        ],
    }

    # Configuration #2: TUN plus the local SOCKS/HTTP proxy.
    tun_config = {
        **common,
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": args.tun_name,
                "address": [
                    "172.19.0.1/30",
                    "fdfe:dcba:9876::1/126",
                ],
                "auto_route": True,
                "auto_redirect": True,
                "strict_route": True,
                "dns_mode": "hijack",
                "stack": "system",
            },
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": args.proxy_host,
                "listen_port": args.proxy_port,
            },
        ],
    }

    return {
        "config-proxy.json": proxy_config,
        "config-tun.json": tun_config,
    }


def write_json_secure(path: Path, config: dict, overwrite: bool) -> None:
    """Write JSON atomically with owner-only permissions (0600)."""
    json_text = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    temporary_path = Path(temporary_name)

    try:
        os.fchmod(file_descriptor, 0o600)
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(json_text)
            output.flush()
            os.fsync(output.fileno())

        if overwrite:
            # os.replace replaces a destination symlink itself, not its target.
            os.replace(temporary_path, path)
        else:
            # A hard link gives an atomic no-overwrite operation on the same filesystem.
            os.link(temporary_path, path)
            temporary_path.unlink()
    except Exception:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert VLESS links into sing-box configurations"
    )
    parser.add_argument("input", help="TXT file containing VLESS links")
    parser.add_argument(
        "--proxy-host",
        type=validate_proxy_host,
        default="127.0.0.1",
        help="Loopback IP address for the local proxy (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--proxy-port",
        type=int,
        default=2080,
        help="Local proxy port (default: 2080)",
    )
    parser.add_argument(
        "--tun-name",
        type=validate_tun_name,
        default="sing0",
        help="TUN interface name (default: sing0)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path.cwd(),
        help="Directory for JSON files (default: current directory)",
    )
    parser.add_argument(
        "--no-urltest",
        action="store_true",
        help="Disable automatic server selection",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing output files",
    )

    args = parser.parse_args()

    if not 1 <= args.proxy_port <= 65535:
        parser.error("Port must be in the range 1–65535")

    source = Path(args.input)
    if not source.is_file():
        parser.error(f"File not found: {source}")

    try:
        lines = source.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError) as error:
        parser.error(f"Failed to read input file: {error}")

    proxies = []
    errors = 0

    print("\nProcessing VLESS links:\n")

    for line_number, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        try:
            proxy = parse_link(line, len(proxies) + 1)
            proxies.append(proxy)
            print(f"[OK] {proxy['name']}")
        except ValueError as error:
            errors += 1
            print(f"[ERROR] Line {line_number}: {error}", file=sys.stderr)

    if not proxies:
        print("\nNo valid VLESS links found.", file=sys.stderr)
        return 1

    output_dir = args.output_dir.expanduser()
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        parser.error(f"Failed to create output directory: {error}")

    if not output_dir.is_dir():
        parser.error(f"Output path is not a directory: {output_dir}")

    configs = build_configs(proxies, args)
    output_paths = [output_dir / filename for filename in configs]

    # Do not accidentally overwrite the input file, including through a symlink.
    try:
        source_resolved = source.resolve(strict=True)
        for output_path in output_paths:
            if output_path.resolve(strict=False) == source_resolved:
                parser.error(f"Output file matches the input file: {output_path}")
    except OSError as error:
        parser.error(f"Failed to validate file paths: {error}")

    if not args.force:
        existing = [path for path in output_paths if os.path.lexists(path)]
        if existing:
            names = ", ".join(str(path) for path in existing)
            parser.error(
                f"The following file(s) already exist: {names}. Use --force to overwrite them."
            )

    try:
        for filename, config in configs.items():
            output_path = output_dir / filename
            write_json_secure(output_path, config, overwrite=args.force)
            print(f"[OK] Created {output_path} (permissions: 600)")
    except OSError as error:
        parser.error(f"Failed to write configuration: {error}")

    print("\n" + "=" * 48)
    print(f"Succeeded: {len(proxies)}")
    print(f"Errors:    {errors}")
    print(f"Proxy:     {args.proxy_host}:{args.proxy_port}")
    print(f"TUN:      {args.tun_name}")
    print(f"Directory: {output_dir}")
    print("=" * 48)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
