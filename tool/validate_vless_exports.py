"""Validate synthetic Flutter exports with official cores; optional local data-plane smoke test.

No VPS, SSH credentials, installed service or real profile is accessed. Obtain the
official core binaries and verify their checksums before passing their paths.
The optional smoke test binds loopback only and requests https://example.com/.
"""
import argparse
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('vless_validation', ROOT / 'server/vless_manager.py')
vless = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vless)


def command(args):
    result = subprocess.run([str(a) for a in args], capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Official core rejected a synthetic configuration.')
    return result.stdout.decode('utf-8', errors='replace')


def exact(sock, size):
    result = b''
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise OSError('Local test proxy closed the connection.')
        result += part
    return result


def request_through_proxy(curl=None):
    if curl is not None:
        # Schannel-backed curl can use the Windows trust store where an
        # isolated Python distribution lacks the required certificate chain.
        result = subprocess.run([str(curl), '--proxy', 'socks5h://127.0.0.1:10808', '--noproxy', '',
            '--connect-timeout', '10', '--max-time', '20', '--silent', '--output', os.devnull,
            '--write-out', '%{http_code}', 'https://example.com/'], capture_output=True, timeout=25)
        if result.returncode or result.stdout not in (b'200', b'301', b'302'):
            raise OSError('Verified HTTPS through the local test proxy failed.')
        return
    with socket.create_connection(('127.0.0.1', 10808), timeout=10) as stream:
        stream.settimeout(15)
        stream.sendall(b'\x05\x01\x00')
        if exact(stream, 2) != b'\x05\x00':
            raise OSError('SOCKS negotiation failed.')
        host = b'example.com'
        stream.sendall(b'\x05\x01\x00\x03' + bytes([len(host)]) + host + b'\x01\xbb')
        header = exact(stream, 4)
        if header[:2] != b'\x05\x00':
            raise OSError('Synthetic VLESS tunnel refused the request.')
        size = {1: 4, 4: 16}.get(header[3])
        if header[3] == 3:
            size = exact(stream, 1)[0]
        if size is None:
            raise OSError('Invalid SOCKS response.')
        exact(stream, size + 2)
        with ssl.create_default_context().wrap_socket(stream, server_hostname='example.com') as tls:
            tls.sendall(b'HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
            response = tls.recv(1024).split(b'\r\n')[0]
            if not response.startswith((b'HTTP/1.1 200', b'HTTP/1.1 301', b'HTTP/1.1 302')):
                raise OSError('No successful HTTPS response through the test tunnel.')


def available(port):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', port))


def start(args, port):
    process = subprocess.Popen([str(a) for a in args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    try:
        for _ in range(50):
            if process.poll() is not None:
                raise RuntimeError('Local core exited before listening.')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                    return process
            except OSError:
                time.sleep(0.1)
        raise RuntimeError('Local core did not start listening.')
    except BaseException:
        stop(process)
        raise


def stop(process):
    if process is not None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--xray', type=Path, required=True)
    parser.add_argument('--sing-box', type=Path, required=True)
    parser.add_argument('--decode-qr', action='store_true', help='Requires Pillow and zxing-cpp.')
    parser.add_argument('--smoke', action='store_true', help='Start loopback cores; access the public Reality target and example.com.')
    parser.add_argument('--curl', type=Path, help='Optional curl executable for HTTPS using its native certificate trust store; verification stays enabled.')
    args = parser.parse_args()
    if 'Xray 26.10.31 ' not in command([args.xray, 'version']) or 'sing-box version 1.14.4' not in command([args.sing_box, 'version']):
        raise RuntimeError('This compatibility check targets Xray 26.10.31 and sing-box 1.14.4 only.')
    xf = args.fixtures / 'xray-client.json'
    sf = args.fixtures / 'sing-box-client.json'
    xc, sc = json.loads(xf.read_text()), json.loads(sf.read_text())
    outbound = xc['outbounds'][0]
    server = outbound['settings']['vnext'][0]
    identity = server['users'][0]['id']
    if server['address'] != '127.0.0.1' or server['port'] != 24443 or identity != '00000000-0000-4000-8000-000000000001':
        raise RuntimeError('Only the documented synthetic loopback fixtures may be used.')
    reality = outbound['streamSettings']['realitySettings']
    link = (args.fixtures / 'link.txt').read_text(encoding='utf-8')
    uri = urlsplit(link); query = {k: v[0] for k, v in parse_qs(uri.query).items()}
    assert uri.scheme == 'vless' and uri.username == identity and uri.hostname == '127.0.0.1' and uri.port == 24443
    assert query == dict(encryption='none', security='reality', type='tcp', sni=reality['serverName'],
                         fp=reality['fingerprint'], pbk=reality['password'], sid=reality['shortId'], flow=vless.FLOW)
    so = sc['outbounds'][0]
    assert so['uuid'] == identity and so['flow'] == vless.FLOW and so['server'] == server['address'] and so['server_port'] == server['port']
    assert so['tls']['server_name'] == reality['serverName'] and so['tls']['utls']['fingerprint'] == reality['fingerprint']
    assert so['tls']['reality']['public_key'] == reality['password'] and so['tls']['reality']['short_id'] == reality['shortId']
    command([args.xray, 'run', '-test', '-config', xf])
    command([args.sing_box, 'check', '-c', sf])
    print('Production-generated link and both client JSON formats: compatible.')
    if args.decode_qr:
        from PIL import Image, ImageOps
        import zxingcpp
        rgba = Image.open(args.fixtures / 'link-qr.png').convert('RGBA')
        image = Image.new('RGBA', rgba.size, 'white'); image.alpha_composite(rgba)
        decoded = zxingcpp.read_barcode(ImageOps.expand(image.convert('RGB'), border=50, fill='white'))
        assert decoded is not None and decoded.text == link
        print('Independently decoded QR: exact link match.')
    # RFC 7748 Alice X25519 test vector; not a deployed credential.
    private = base64.urlsafe_b64encode(bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')).decode().rstrip('=')
    state = dict(schema=1, owner='Ashapp', address='127.0.0.1', port=24443,
                 sni=reality['serverName'], fingerprint=reality['fingerprint'],
                 private_key=private, public_key=reality['password'], clients=[
                     dict(name='First synthetic device', uuid=identity, short_id=reality['shortId']),
                     dict(name='Second synthetic device', uuid='00000000-0000-4000-8000-000000000002', short_id='1123456789abcdef')])
    with tempfile.TemporaryDirectory(prefix='ashapp-core-test-') as temporary:
        config_path = Path(temporary) / 'server.json'
        def save_server(value):
            cfg = vless.server_config(value)
            cfg['inbounds'][0]['listen'] = '127.0.0.1'
            config_path.write_text(vless.encoded(cfg), encoding='utf-8')
            command([args.sing_box, 'check', '-c', config_path])
        empty = copy.deepcopy(state); empty['clients'] = []
        save_server(empty)
        save_server(state)
        print('Production-generated server JSON: accepted by sing-box.')
        if not args.smoke:
            return
        available(24443); available(10808)
        server_process = client_process = None
        try:
            server_process = start([args.sing_box, 'run', '-c', config_path], 24443)
            for label, core_args in [('Xray', [args.xray, 'run', '-config', xf]), ('sing-box', [args.sing_box, 'run', '-c', sf])]:
                client_process = start(core_args, 10808)
                request_through_proxy(args.curl)
                stop(client_process); client_process = None
                print(label + ' client -> local sing-box Reality + Vision -> HTTPS: passed.')
            stop(server_process); server_process = None
            revoked = copy.deepcopy(state); revoked['clients'].pop(0); save_server(revoked)
            server_process = start([args.sing_box, 'run', '-c', config_path], 24443)
            client_process = start([args.xray, 'run', '-config', xf], 10808)
            try:
                request_through_proxy(args.curl)
            except (OSError, ssl.SSLError):
                print('Revoked device cannot pass HTTPS traffic: passed.')
            else:
                raise RuntimeError('Revoked synthetic client still has access.')
            stop(client_process); client_process = None
            client_process = start([args.xray, 'run', '-config', args.fixtures / 'xray-second-client.json'], 10808)
            request_through_proxy(args.curl)
            print('Other device keeps valid access after revocation: passed.')
        finally:
            stop(client_process); stop(server_process)


if __name__ == '__main__':
    main()
