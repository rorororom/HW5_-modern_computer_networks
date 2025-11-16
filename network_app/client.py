# network_app/client.py
import argparse
import socket
import sys
from typing import Optional, Tuple, Union

from .tls_utils import make_client_context


Address = Tuple[str, int]
SocketLike = Union[socket.socket, "ssl.SSLSocket"]  # type: ignore[name-defined]


def interactive_talk(sock: SocketLike) -> None:
    """
    Простая интерактивная сессия:
    - читает строки из stdin, отправляет на сервер, печатает ответ
    - 'quit' завершает сессию
    """
    try:
        with sock:
            file_r = sock.makefile("rb", buffering=0)
            file_w = sock.makefile("wb", buffering=0)

            print("[client] enter lines to send. type 'quit' to exit.")
            for line in sys.stdin:
                data = line.encode("utf-8")
                file_w.write(data if data.endswith(b"\n") else data + b"\n")
                file_w.flush()

                resp = file_r.readline()
                if not resp:
                    print("[client] server closed connection")
                    return
                print("[client] response:", resp.decode("utf-8", errors="replace").rstrip("\r\n"))

                if line.strip().lower() == "quit":
                    return
    except KeyboardInterrupt:
        print("\n[client] interrupted")
    except Exception as e:
        print(f"[client] error: {e!r}")


def run_tcp_client(
    host: str = "127.0.0.1",
    port: int = 8888,
    use_tls: bool = False,
    cafile: Optional[str] = None,
    insecure: bool = False,
    server_name: Optional[str] = None,
) -> None:
    """
    Подключается к серверу и запускает интерактивный обмен.
    Если use_tls=True — соединение оборачивается в TLS.
    - cafile: путь к PEM корням (для проверки самоподписанного сертификата сервера)
    - insecure: отключить проверку сертификата (только для локального теста!)
    - server_name: SNI (по умолчанию host)
    """
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if use_tls:
        ctx = make_client_context(cafile=cafile, insecure=insecure)
        sni = server_name or host
        sock = ctx.wrap_socket(raw, server_hostname=sni)
        sock.connect((host, port))
        try:
            cipher = getattr(sock, "cipher", None)
            if callable(cipher):
                name, proto, bits = cipher()  # type: ignore[misc]
                print(f"[client] TLS connected to {host}:{port} (SNI={sni}) cipher={name} proto={proto} bits={bits}")
            else:
                print(f"[client] TLS connected to {host}:{port} (SNI={sni})")
        except Exception:
            print(f"[client] TLS connected to {host}:{port} (SNI={sni})")
    else:
        raw.connect((host, port))
        sock = raw
        print(f"[client] connected to {host}:{port}")

    interactive_talk(sock)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Simple TCP client with optional TLS")
    p.add_argument("--host", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=8888, help="Server port (default: 8888)")
    p.add_argument("--tls", action="store_true", help="Enable TLS")
    p.add_argument("--cafile", type=str, help="Path to CA bundle (PEM)")
    p.add_argument("--insecure", action="store_true", help="Disable certificate verification (for testing only)")
    p.add_argument("--sni", type=str, help="Override SNI (server_hostname)")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_tcp_client(
        host=args.host,
        port=args.port,
        use_tls=args.tls,
        cafile=args.cafile,
        insecure=args.insecure,
        server_name=args.sni,
    )
