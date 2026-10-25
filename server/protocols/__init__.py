import importlib
import pkgutil

from .base import Protocol

PROTOCOLS: dict[str, Protocol] = {}


def _discover():
    for mod in pkgutil.iter_modules(__path__):
        if mod.name.startswith("_") or mod.name == "base":
            continue
        module = importlib.import_module(f"{__name__}.{mod.name}")
        proto = getattr(module, "PROTOCOL", None)
        if isinstance(proto, Protocol):
            PROTOCOLS[proto.id] = proto


def get(protocol_id: str) -> Protocol:
    if protocol_id not in PROTOCOLS:
        raise KeyError(f"Неизвестный протокол: {protocol_id}")
    return PROTOCOLS[protocol_id]


_discover()
