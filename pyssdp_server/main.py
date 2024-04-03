import asyncio
import datetime
import logging
import platform
import socket
import struct
import textwrap
import typing
from urllib.parse import urlparse
import uuid

import ifaddr
import ssdp
import ssdp.network

from . import services

IPAddress: typing.TypeAlias = tuple[str, int]

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger('SSDPServer')
logger.setLevel(logging.DEBUG)


def parse_location(location: str) -> str:
    parsed = urlparse(location)._replace(scheme='http')
    return parsed.geturl()


class ServerSettings:
    LOCATION: str = parse_location('http://192.168.1.101:9000/dev0/device_detail.xml')
    SERVER: str = '{p.system}/{p.release}, UPnP/1.0, PyUPnPServer for UPnP devices/1.0'.format(p=platform.uname())
    UUID: str = f'uuid:{uuid.uuid5(uuid.uuid5(uuid.NAMESPACE_DNS, SERVER), LOCATION)}'
    URN: str = services.URN
    CACHE_CONTROL: str = 'max-age=1800'
    PORT = ssdp.network.PORT

    @staticmethod
    def get_date() -> str:
        return f'{datetime.datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")}'

    @classmethod
    def get_headers(cls) -> dict[str, str]:
        return {
            'LOCATION': cls.LOCATION,
            'CACHE-CONTROL': cls.CACHE_CONTROL,
            'SERVER': cls.SERVER
        }


class SSDPServiceProtocol(ssdp.aio.SimpleServiceDiscoveryProtocol, ServerSettings):
    def __init__(self):
        super().__init__()
        self.fixed_headers = {**self.get_headers(), 'EXT': ''}

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        sock: socket.socket = self.transport.get_extra_info('socket')
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        for adpter in ifaddr.get_adapters():
            for addr in adpter.ips:
                if addr.is_IPv4 and addr.ip != '127.0.0.1':
                    mreqn = struct.pack(
                        '4s4si', socket.inet_aton(ssdp.network.MULTICAST_ADDRESS_IPV4), socket.inet_aton(addr.ip), 0
                    )
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreqn)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        msg = ssdp.messages.SSDPMessage.parse(data.decode())
        if isinstance(msg, ssdp.messages.SSDPResponse):
            self.response_received(msg, addr)
        else:
            self.request_received(msg, addr)

    def response_received(self, response: ssdp.messages.SSDPResponse, addr: IPAddress) -> None:
        ...

    def request_received(self, request: ssdp.messages.SSDPRequest, addr: IPAddress) -> None:
        method = request.method
        if method == 'NOTIFY':
            logger.info(f'"NOTIFY" from {addr[0]}:{addr[1]!s}')
            return
        if method == 'M-SEARCH':
            return self.handle_msearch(request, addr)

    def handle_msearch(self, request: ssdp.messages.SSDPRequest, addr: IPAddress) -> None:
        logger.info(f'"M-SEARCH" from {addr[0]}:{addr[1]!s}')
        logger.debug(textwrap.indent(str(request), '    '))
        for k, v in request.headers:
            if k == 'ST':
                service_type = v
                break
        if service_type == 'ssdp:all':
            target_services = services.all_services
        else:
            try:
                target_services = {
                    next(service for service in services.all_services if service.service_type == service_type)
                }
            except StopIteration:
                target_services = set()
        for service in target_services:
            response = self.get_msearch_response(service)
            logger.info(f'"M-SEARCH RESPONSE" to {addr[0]}:{addr[1]!s}')
            logger.debug(textwrap.indent(str(response), '    '))
            response.sendto(self.transport, addr)

    def get_msearch_response(self, service: services.Service) -> ssdp.messages.SSDPResponse:
        return ssdp.messages.SSDPResponse(
            status_code=200,
            reason='OK',
            headers={
                **self.fixed_headers,
                'DATE': self.get_date(),
                'ST': service.service_type,
                'USN': f'{self.UUID}::{service.service_type}'
            }
        )


class SSDPAdvertiser(ServerSettings):
    def __init__(self, ip: typing.Optional[IPAddress] = None, interval: int = 60):
        self.ip: IPAddress = ip if ip is not None else (ssdp.network.MULTICAST_ADDRESS_IPV4, self.PORT)
        self.host: str = f'{self.ip[0]}:{self.ip[1]!s}'
        self.interval: int = interval
        self.fixed_headers = {
            **ServerSettings.get_headers(),
            'HOST': self.host,
            'NT': ServerSettings.URN,
            'NTS': 'ssdp:alive',
            'USN': f'{self.UUID}::{self.URN}'
        }

    async def broadcast(self, transport: asyncio.DatagramTransport):
        host = self.host
        headers = self.fixed_headers
        while True:
            # family, addr = ssdp.network.get_best_family(None, ssdp.network.PORT)
            request = ssdp.messages.SSDPRequest(method='NOTIFY', headers=headers)
            logger.info(f'"NOTIFY" to {host}')
            logger.debug(textwrap.indent(str(request), '    '))
            request.sendto(transport, self.ip)
            await asyncio.sleep(self.interval)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='SSDP Server',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('location', default=None, help='The URL for UPnP description XML of this device.')
    parser.add_argument(
        '--port', default=1900, type=int,
        help='The UDP port for SSDP (Simple Service Discovery Protocol). Please exercise caution when modifying.'
    )
    parser.add_argument('--interval', default=60, help='Broadcast interval for advertising the UPnP server.')
    parser.add_argument('--log-level', default='INFO', choices=list(logging.getLevelNamesMapping()))

    args = parser.parse_args()
    logger.setLevel(args.log_level)
    if args.location is not None:
        ServerSettings.LOCATION = parse_location(args.location)
    ServerSettings.PORT = args.port

    loop = asyncio.new_event_loop()
    ssdp_advertiser = SSDPAdvertiser(interval=args.interval)

    connect = loop.create_datagram_endpoint(
        lambda: SSDPServiceProtocol(),
        family=socket.AF_INET,
        local_addr=('0.0.0.0', ServerSettings.PORT),
    )
    transport, protocol = loop.run_until_complete(connect)

    loop.create_task(ssdp_advertiser.broadcast(transport), name='SSDP Advertisment')

    logger.debug('SSDPService Details:')
    for k, v in protocol.fixed_headers.items():
        logger.debug(f'    {k}: {v}')
    logger.debug('SSDPAdvertiser Details:')
    for k, v in ssdp_advertiser.fixed_headers.items():
        logger.debug(f'    {k}: {v}')

    try:
        logger.info('Start SSDP Server')
        loop.run_forever()
    except KeyboardInterrupt:
        ...
    finally:
        transport.close()
        loop.close()
        logger.info('Stop SSDP Server')


if __name__ == "__main__":
    main()
