"""Inspect the certificate message and staple received in one TLS 1.3 handshake."""

import ctypes as C
import hashlib
import signal
import socket
import sys


lib = C.CDLL("libssl.so.3")
ptr = C.c_void_p


def api(name, result, *args):
    fn = getattr(lib, name)
    fn.restype = result
    fn.argtypes = args
    return fn


def probe(port, ca, algorithm, status, signature, issuer=False):
    msg_callback = C.CFUNCTYPE(None, C.c_int, C.c_int, C.c_int, ptr,
                               C.c_size_t, ptr, ptr)
    negotiated = None

    @msg_callback
    def message(write, version, kind, data, length, ssl, arg):
        nonlocal negotiated
        if write or kind != 22 or length < 6:
            return
        header = C.string_at(data, 6)
        if header[0] == 25:
            negotiated = int.from_bytes(header[4:6], "big")
        elif header[0] == 11:
            negotiated = 0

    method = api("TLS_client_method", ptr)()
    ctx = api("SSL_CTX_new", ptr, ptr)(method)
    assert ctx
    try:
        assert api("SSL_CTX_load_verify_locations", C.c_int, ptr, C.c_char_p,
                   C.c_char_p)(ctx, ca.encode(), None)
        api("SSL_CTX_set_verify", None, ptr, C.c_int, ptr)(ctx, 1, None)
        alg = C.c_int(algorithm)
        if algorithm:
            assert api("SSL_CTX_set1_cert_comp_preference", C.c_int, ptr,
                       C.POINTER(C.c_int), C.c_size_t)(ctx, C.byref(alg), 1)
        else:
            api("SSL_CTX_set_options", C.c_uint64, ptr, C.c_uint64)(ctx, 1 << 33)
        api("SSL_CTX_set_msg_callback", None, ptr, msg_callback)(ctx, message)
        ssl = api("SSL_new", ptr, ptr)(ctx)
        assert ssl
        try:
            ctrl = api("SSL_ctrl", C.c_long, ptr, C.c_int, C.c_long, ptr)
            assert ctrl(ssl, 123, 0x304, None)  # TLS 1.3 minimum
            assert ctrl(ssl, 124, 0x304, None)  # TLS 1.3 maximum
            assert ctrl(ssl, 55, 0, b"ocsp.test")  # SNI
            assert ctrl(ssl, 98, 0, signature.encode())
            assert api("SSL_set1_host", C.c_int, ptr, C.c_char_p)(ssl, b"ocsp.test")
            if status:
                assert ctrl(ssl, 65, 1, None)  # OCSP status_request
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.setblocking(True)
                assert api("SSL_set_fd", C.c_int, ptr, C.c_int)(ssl, sock.fileno())
                assert api("SSL_connect", C.c_int, ptr)(ssl) == 1
                assert api("SSL_get_verify_result", C.c_long, ptr)(ssl) == 0
                data = ptr()
                length = ctrl(ssl, 70, 0, C.byref(data))
                staple = C.string_at(data, length) if length > 0 else None
                assert negotiated is not None
                result = [str(negotiated), hashlib.sha256(staple).hexdigest() if staple else "-"]
                if issuer:
                    chain = api("SSL_get_peer_cert_chain", ptr, ptr)(ssl)
                    cert = api("OPENSSL_sk_value", ptr, ptr, C.c_int)(chain, 1)
                    assert cert
                    encode = api("i2d_X509", C.c_int, ptr, C.POINTER(ptr))
                    size = encode(cert, None)
                    assert size > 0
                    der = C.create_string_buffer(size)
                    dest = ptr(C.addressof(der))
                    assert encode(cert, C.byref(dest)) == size
                    result.append(hashlib.sha256(der.raw).hexdigest())
                print(" ".join(result))
        finally:
            api("SSL_free", None, ptr)(ssl)
    finally:
        api("SSL_CTX_free", None, ptr)(ctx)


if __name__ == "__main__":
    signal.alarm(8)
    probe(int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4]),
          sys.argv[5], len(sys.argv) > 6)
