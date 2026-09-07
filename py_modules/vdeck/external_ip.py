"""Explicit, bounded HTTPS checks of the device's current public IPv4."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import ssl
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .errors import VDeckError

# Fixed destinations; no credentials, config, query parameters or ambient proxy.
IP_PROVIDERS = ("https://api.ipify.org", "https://ipv4.icanhazip.com")
SYSTEM_CA_FILES = (
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/ssl/certs/ca-bundle.crt",
)


def host_tls_context(logger: logging.Logger) -> ssl.SSLContext:
    """Use SteamOS trust, not the frozen interpreter's build-time CA path.

    PROTOCOL_TLS_CLIENT retains certificate AND hostname verification and does
    not enable SSLKEYLOGFILE from the parent environment.
    """
    if not sys.platform.startswith("linux"):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_default_certs()
        logger.info("external IP TLS trust source=platform ca_count=%d", context.cert_store_stats()["x509_ca"])
        return context
    for cafile in SYSTEM_CA_FILES:
        try:
            if not Path(cafile).is_file():
                continue
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cafile=cafile)
            count = context.cert_store_stats()["x509_ca"]
            if not count:
                continue
            logger.info("external IP TLS trust source=host cafile=%s ca_count=%d", cafile, count)
            return context
        except (OSError, ValueError) as exc:
            logger.warning("external IP CA load failed cafile=%s exception=%s", cafile, type(exc).__name__)
    logger.warning("external IP TLS trust failed code=EXTERNAL_IP_CA_UNAVAILABLE")
    raise VDeckError("EXTERNAL_IP_CA_UNAVAILABLE", "The system TLS trust store could not be loaded")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _lookup(logger: logging.Logger, cancelled: threading.Event) -> dict[str, str]:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirect(),
        urllib.request.HTTPSHandler(context=host_tls_context(logger)),
    )
    tls_failure = False
    for provider in IP_PROVIDERS:
        if cancelled.is_set():
            break
        try:
            request = urllib.request.Request(  # noqa: S310 -- fixed HTTPS-only allowlist above
                provider, headers={"User-Agent": "V-Deck/0.1.0", "Accept": "text/plain"}
            )
            with opener.open(request, timeout=4) as response:
                raw = response.read(65)
                if len(raw) > 64:
                    raise ValueError("Oversized IP response")
                address = ipaddress.ip_address(raw.decode("ascii").strip())
                if address.version != 4 or not address.is_global:
                    raise ValueError("Expected public IPv4")
            # Never log the returned address, body or arbitrary exception text.
            logger.info("external IP request succeeded provider=%s family=IPv4", provider)
            return {"ip": str(address), "provider": provider, "family": "IPv4"}
        except (OSError, ValueError, urllib.error.URLError) as exc:
            reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            errno = getattr(reason, "errno", None)
            verify_code = getattr(reason, "verify_code", None)
            tls_failure = tls_failure or isinstance(reason, ssl.SSLCertVerificationError)
            logger.warning(
                "external IP request failed provider=%s code=EXTERNAL_IP_PROVIDER_FAILED "
                "exception=%s reason=%s errno=%s verify_code=%s",
                provider,
                type(exc).__name__,
                type(reason).__name__,
                errno if isinstance(errno, int) else None,
                verify_code if isinstance(verify_code, int) else None,
            )
    if tls_failure:
        raise VDeckError("EXTERNAL_IP_TLS_FAILED", "TLS certificate verification failed; see technical log")
    raise VDeckError("EXTERNAL_IP_UNAVAILABLE", "External IP services are unavailable; check network access")


async def lookup_external_ip(logger: logging.Logger) -> dict[str, str]:
    cancelled = threading.Event()
    try:
        return await asyncio.wait_for(asyncio.to_thread(_lookup, logger, cancelled), 10)
    except asyncio.TimeoutError as exc:
        logger.warning("external IP request failed code=EXTERNAL_IP_TIMEOUT")
        raise VDeckError("EXTERNAL_IP_TIMEOUT", "External IP request timed out") from exc
    finally:
        # A libc DNS call cannot be cancelled from Python. Do not let a late
        # worker try another provider after its caller timed out or left.
        cancelled.set()
