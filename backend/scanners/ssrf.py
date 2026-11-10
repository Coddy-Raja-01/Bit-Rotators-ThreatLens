import socket
import ipaddress
import re
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter

# Disallowed private, link-local, cloud metadata, and special network ranges
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("10.0.0.0/8"),         # Private-Use (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local (Cloud metadata)
    ipaddress.ip_network("172.16.0.0/12"),      # Private-Use (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),     # Private-Use (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Network Interconnect Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

ALLOWED_PORTS = {80, 443, 8080, 8443}
ALLOWED_SCHEMES = {"http", "https"}

class SSRFSecurityException(Exception):
    """Raised when an address fails SSRF safety validation."""
    pass

class HostUnresolvableException(Exception):
    """Raised when hostname cannot be resolved in DNS."""
    pass

def parse_obfuscated_ip(host_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """
    Attempts to decode obfuscated IP formats (integer, hex, octal, dotted-hex).
    e.g. 2130706433 -> 127.0.0.1, 0x7f.0.0.1 -> 127.0.0.1
    """
    clean = host_str.strip()
    
    # Standard decimal / IPv6
    try:
        return ipaddress.ip_address(clean)
    except ValueError:
        pass

    # Decimal integer IP: e.g. 2130706433
    if clean.isdigit():
        try:
            val = int(clean)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass

    # Hex single integer: e.g. 0x7f000001
    if clean.lower().startswith("0x"):
        try:
            val = int(clean, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass

    # Dotted octal or hex components: e.g. 0177.0.0.1 or 0x7f.0.0.1
    parts = clean.split(".")
    if len(parts) == 4:
        try:
            int_parts = []
            for p in parts:
                p_lower = p.lower()
                if p_lower.startswith("0x"):
                    int_parts.append(int(p_lower, 16))
                elif p_lower.startswith("0") and len(p_lower) > 1:
                    int_parts.append(int(p_lower, 8))
                else:
                    int_parts.append(int(p_lower, 10))
            if all(0 <= x <= 255 for x in int_parts):
                ip_str = ".".join(str(x) for x in int_parts)
                return ipaddress.IPv4Address(ip_str)
        except Exception:
            pass

    return None

def is_ip_blocked(ip_obj_or_str) -> tuple[bool, str]:
    """Check if an IP address belongs to any blocked/private network range."""
    if isinstance(ip_obj_or_str, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        ip = ip_obj_or_str
    else:
        ip = parse_obfuscated_ip(str(ip_obj_or_str))
        if ip is None:
            return True, f"Invalid IP address representation: {ip_obj_or_str}"

    # Check IPv4-mapped IPv6
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return is_ip_blocked(ip.ipv4_mapped)

    if ip.is_loopback:
        return True, f"Loopback address forbidden: {ip}"
    if ip.is_private:
        return True, f"Private/Internal RFC-1918 address forbidden: {ip}"
    if ip.is_link_local:
        return True, f"Link-local / Cloud metadata address forbidden: {ip}"
    if ip.is_multicast:
        return True, f"Multicast address forbidden: {ip}"
    if ip.is_reserved:
        return True, f"Reserved address forbidden: {ip}"

    for net in BLOCKED_NETWORKS:
        if ip in net:
            return True, f"Target IP {ip} falls inside blocked range {net}"

    return False, ""

def validate_target_host(hostname: str) -> list[str]:
    """
    Resolve hostname to IP addresses and assert every returned IP is public and safe.
    Returns list of validated public IPs.
    """
    clean_host = hostname.strip().lower()
    
    # Strip port if present
    if ":" in clean_host and not clean_host.startswith("["):
        clean_host = clean_host.split(":")[0]

    # Explicit blocked domain patterns
    if clean_host in {
        "localhost", "localhost.localdomain", "broadcasthost",
        "metadata.google.internal", "metadata", "instance-data"
    }:
        raise SSRFSecurityException(f"Forbidden local or cloud metadata hostname: {clean_host}")
        
    if clean_host.endswith(".local") or clean_host.endswith(".internal"):
        raise SSRFSecurityException(f"Forbidden internal domain suffix: {clean_host}")

    # Check if host itself is an obfuscated IP literal
    obfuscated_ip = parse_obfuscated_ip(clean_host)
    if obfuscated_ip:
        blocked, reason = is_ip_blocked(obfuscated_ip)
        if blocked:
            raise SSRFSecurityException(f"Security validation blocked: {reason}")
        return [str(obfuscated_ip)]

    try:
        # Resolve all IPv4 and IPv6 addresses
        addr_info = socket.getaddrinfo(clean_host, None)
    except socket.gaierror as e:
        raise HostUnresolvableException(f"Host '{clean_host}' could not be resolved via DNS: {e}")

    if not addr_info:
        raise HostUnresolvableException(f"No IP addresses resolved for host '{clean_host}'")

    resolved_ips = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip = sockaddr[0]
        blocked, reason = is_ip_blocked(ip)
        if blocked:
            raise SSRFSecurityException(f"Security validation blocked: {reason}")
        if ip not in resolved_ips:
            resolved_ips.append(ip)

    return resolved_ips

def validate_url_for_scan(raw_url: str) -> tuple[str, str, list[str], bool]:
    """
    Validates a URL before any network operation.
    Validates scheme, port, and hostname.
    Returns normalized (url, hostname, resolved_ips, is_live_dns).
    """
    url = raw_url.strip()
    if not url:
        raise SSRFSecurityException("Empty URL provided")
        
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise SSRFSecurityException(f"Disallowed URI scheme: '{parsed.scheme}'. Only http and https are allowed.")

    port = parsed.port
    if port and port not in ALLOWED_PORTS:
        raise SSRFSecurityException(f"Disallowed port: {port}. Only standard web ports (80, 443, 8080, 8443) are permitted.")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFSecurityException("URL is missing a valid hostname")

    try:
        resolved_ips = validate_target_host(hostname)
        return url, hostname, resolved_ips, True
    except HostUnresolvableException:
        # Allow domain analysis to proceed for offline / taken-down domains
        return url, hostname, [], False


class DNSRebindingProtectedAdapter(HTTPAdapter):
    """
    HTTPAdapter that pins socket connection to a pre-validated public IP address,
    defeating DNS rebinding (TOCTOU) attacks completely.
    """
    def __init__(self, pinned_ip: str, hostname: str | None = None, *args, **kwargs):
        self.pinned_ip = pinned_ip
        self.hostname = hostname.lower() if hostname else None
        super().__init__(*args, **kwargs)

    def _connection_for_url(self, url: str, proxies=None):
        if proxies:
            raise SSRFSecurityException("Pinned target requests cannot use an outbound proxy")
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        if not hostname or (self.hostname and hostname != self.hostname):
            raise SSRFSecurityException("Pinned connection hostname does not match the validated target")

        pool_kwargs = {}
        if parsed.scheme == "https":
            pool_kwargs["assert_hostname"] = hostname
            pool_kwargs["server_hostname"] = hostname
        return self.poolmanager.connection_from_host(
            self.pinned_ip,
            port=parsed.port,
            scheme=parsed.scheme,
            pool_kwargs=pool_kwargs
        )

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        parsed = urlparse(request.url)
        if parsed.hostname:
            host_header = parsed.hostname
            if parsed.port:
                host_header = f"{host_header}:{parsed.port}"
            request.headers["Host"] = host_header
        return self._connection_for_url(request.url, proxies)

    def get_connection(self, url, proxies=None):
        return self._connection_for_url(url, proxies)

def create_pinned_session(pinned_ip: str, hostname: str | None = None) -> requests.Session:
    """Creates a requests session pinned to a specific pre-validated IP address."""
    session = requests.Session()
    session.trust_env = False
    adapter = DNSRebindingProtectedAdapter(pinned_ip, hostname)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session
