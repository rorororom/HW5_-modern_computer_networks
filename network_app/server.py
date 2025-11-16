# network_app/server.py
import argparse
import os
import socket
import threading
from typing import Optional, Tuple, Union

from .tls_utils import make_server_context


Address = Tuple[str, int]
SocketLike = Union[socket.socket, "ssl.SSLSocket"]  # type: ignore[name-defined]


def handle_client(conn: SocketLike, addr: Address) -> None:
    try:
        with conn:
            # Попробуем вывести базовую TLS-инфу, если это TLS-сокет
            try:
                # у SSLSocket есть метод cipher()
                cipher = getattr(conn, "cipher", None)
                if callable(cipher):
                    name, proto, bits = cipher()  # type: ignore[misc]
                    print(f"[server] TLS: cipher={name} proto={proto} bits={bits} from {addr}")
            except Exception:
                pass

            file = conn.makefile("rwb", buffering=0)
            while True:
                line = file.readline()
                if not line:
                    # клиент закрыл соединение
                    print(f"[server] {addr} disconnected")
                    return
                # удаляем завершающий \r?\n и декодируем
                text = line.rstrip(b"\r\n").decode("utf-8", errors="replace")
                print(f"[server] recv from {addr}: {text!r}")

                if text.strip().lower() == "quit":
                    file.write(b"OK bye\n")
                    file.flush()
                    print(f"[server] close {addr}")
                    return

                response = f"OK {text}\n".encode("utf-8")
                file.write(response)
                file.flush()
    except Exception as e:
        print(f"[server] error with {addr}: {e!r}")


def run_tcp_server(
    host: str = "0.0.0.0",
    port: int = 8888,
    use_tls: bool = False,
    certfile: Optional[str] = None,
    keyfile: Optional[str] = None,
    cafile: Optional[str] = None,
) -> None:
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind((host, port))
    srv_sock.listen(128)

    print(
        f"[server] listening on {host}:{port}"
        + (" with TLS" if use_tls else "")
    )

    tls_ctx = None
    if use_tls:
        certfile = certfile or os.environ.get("TLS_CERT", "server.crt")
        keyfile = keyfile or os.environ.get("TLS_KEY", "server.key")
        if not certfile or not keyfile:
            raise RuntimeError("TLS enabled but no cert/key provided (use --cert/--key or TLS_CERT/TLS_KEY)")
        tls_ctx = make_server_context(certfile=certfile, keyfile=keyfile, cafile=cafile)

    try:
        while True:
            conn, addr = srv_sock.accept()
            print(f"[server] connection from {addr}")

            if use_tls and tls_ctx is not None:
                try:
                    # серверная обёртка
                    conn = tls_ctx.wrap_socket(conn, server_side=True)
                except Exception as e:
                    print(f"[server] TLS handshake failed for {addr}: {e!r}")
                    conn.close()
                    continue

            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    finally:
        srv_sock.close()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Simple TCP server with optional TLS")
    p.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    p.add_argument("--port", type=int, default=8888, help="TCP port (default: 8888)")
    p.add_argument("--tls", action="store_true", help="Enable TLS")
    p.add_argument("--cert", type=str, help="Path to server certificate (PEM)")
    p.add_argument("--key", type=str, help="Path to server private key (PEM)")
    p.add_argument("--cafile", type=str, help="Path to CA bundle (optional)")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_tcp_server(
        host=args.host,
        port=args.port,
        use_tls=args.tls,
        certfile=args.cert,
        keyfile=args.key,
        cafile=args.cafile,
    )
