from typing import Self, NamedTuple

URN = 'urn:schemas-upnp-org:device:MediaServer:1'


class Service(NamedTuple):
    service_type: str

    @classmethod
    def create(cls, service_name: str, domain: str = '', version: int = 1) -> Self:
        return cls(f'urn:{domain or "schemas-upnp-org"}:service:{service_name}:{version}')


all_services = {
    Service(URN),
    Service.create('ContentDirectory'),
    Service.create('ConnectionManager'),
    # Service.create('X_MS_MediaReceiverRegistrar', 'microsoft.com', 1)
}
