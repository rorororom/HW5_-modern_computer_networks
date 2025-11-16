# network_app/tls_utils.py
import os
import ssl
from typing import Optional


def make_server_context(
    certfile: str,
    keyfile: str,
    cafile: Optional[str] = None,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_COMPRESSION
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

    if cafile:
        ctx.load_verify_locations(cafile=cafile)
        ctx.verify_mode = ssl.CERT_OPTIONAL

    _maybe_enable_keylog(ctx)
    return ctx


def make_client_context(
    cafile: Optional[str] = None,
    insecure: bool = False,
) -> ssl.SSLContext:
    if insecure:
        ctx = ssl._create_unverified_context()
        _maybe_enable_keylog(ctx)
        return ctx

    if cafile:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    else:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    _maybe_enable_keylog(ctx)
    return ctx


def _maybe_enable_keylog(ctx: ssl.SSLContext) -> None:
    keylog = os.environ.get("SSLKEYLOGFILE")
    if not keylog:
        return

    try:
        ctx.keylog_filename = keylog
    except Exception:
        if hasattr(ctx, "set_keylog_filename"):
            try:
                ctx.set_keylog_filename(keylog)
            except Exception:
                pass
