import socket


def get_default_interface_ipv4(addr="8.8.8.8") -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((addr, 53))
    except OSError:
        return ""
    else:
        return s.getsockname()[0]
    finally:
        s.close()


def get_default_interface_ipv6(addr="2001:4860:4860::8888") -> str:
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        s.connect((addr, 53))
    except OSError:
        return ""
    else:
        return s.getsockname()[0]
    finally:
        s.close()
