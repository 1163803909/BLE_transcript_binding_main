# src/hci/connection.py

"""
Connection-handle registry for Bluetooth LE HCI events.

This module maps controller-assigned ACL connection handles to the peer
identity observed in LE Connection Complete events.

It intentionally does not:

* open an HCI socket;
* send ACL data;
* infer a peer from an arbitrary handle;
* resolve private addresses;
* perform IRK-based address resolution;
* authorize a target unless the caller explicitly configures one.

Recommended flow:

    registry = ConnectionRegistry()

    event = parse_known_hci_event(raw_hci_event)
    registry.process_event(event)

    connection = registry.require_target(
        peer_address="AA:BB:CC:DD:EE:FF",
        peer_address_type=LE_ADDR_TYPE_PUBLIC,
    )

    handle = connection.handle

The returned handle should then be used to construct an ACL packet.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from threading import RLock
from time import monotonic_ns
from typing import Final, Iterable

from .events import (
    CommandComplete,
    CommandStatus,
    DisconnectionComplete,
    HCIEvent,
    LEConnectionComplete,
    LEEnhancedConnectionComplete,
    LEMetaEvent,
    LE_ADDR_TYPE_PUBLIC,
    LE_ADDR_TYPE_PUBLIC_IDENTITY,
    LE_ADDR_TYPE_RANDOM,
    LE_ADDR_TYPE_RANDOM_IDENTITY,
    format_bd_addr,
    parse_known_hci_event,
)


MAX_CONNECTION_HANDLE: Final[int] = 0x0FFF


class ConnectionRegistryError(RuntimeError):
    """Base exception for connection-registry errors."""


class UnknownConnectionError(ConnectionRegistryError):
    """Raised when a requested handle or target is not known."""


class AmbiguousConnectionError(ConnectionRegistryError):
    """Raised when a target matches more than one active connection."""


class ConnectionAuthorizationError(ConnectionRegistryError):
    """Raised when a connection does not match the authorized target."""


class ConnectionStateError(ConnectionRegistryError):
    """Raised when an invalid connection-state transition is observed."""


@dataclass(frozen=True, slots=True)
class LEConnection:
    """
    Active LE connection observed from a Connection Complete event.

    ``handle`` is the controller-assigned 12-bit HCI ACL connection handle.
    ``peer_address`` is normalized to uppercase colon-separated notation.
    """

    handle: int
    role: int
    peer_address: str
    peer_address_type: int
    connected_at_ns: int
    source_event: str = "unknown"
    connection_interval: int | None = None
    peripheral_latency: int | None = None
    supervision_timeout: int | None = None
    central_clock_accuracy: int | None = None
    local_resolvable_private_address: str | None = None
    peer_resolvable_private_address: str | None = None

    @property
    def connection_handle(self) -> int:
        """Alias for the HCI ACL connection handle."""

        return self.handle

    @property
    def handle_hex(self) -> str:
        """Return the handle in canonical hexadecimal form."""

        return f"0x{self.handle:03x}"

    @property
    def peer_address_type_name(self) -> str:
        """Return a readable address-type name."""

        names = {
            LE_ADDR_TYPE_PUBLIC: "public",
            LE_ADDR_TYPE_RANDOM: "random",
            LE_ADDR_TYPE_PUBLIC_IDENTITY: "public_identity",
            LE_ADDR_TYPE_RANDOM_IDENTITY: "random_identity",
        }

        return names.get(
            self.peer_address_type,
            f"unknown_0x{self.peer_address_type:02x}",
        )

    def matches(
        self,
        *,
        peer_address: str | None = None,
        peer_address_type: int | None = None,
    ) -> bool:
        """
        Return whether this connection matches the supplied target.

        Address comparison is case-insensitive and ignores ``-`` and spaces.
        """

        if peer_address is not None:
            if normalize_bd_addr(peer_address) != self.peer_address:
                return False

        if peer_address_type is not None:
            if peer_address_type != self.peer_address_type:
                return False

        return True


@dataclass(frozen=True, slots=True)
class ConnectionSnapshot:
    """Immutable snapshot of all currently active connections."""

    connections: tuple[LEConnection, ...]

    @property
    def count(self) -> int:
        return len(self.connections)


class ConnectionRegistry:
    """
    Thread-safe registry of active LE connections.

    The registry is deliberately conservative:

    * a handle is inserted only after a successful Connection Complete event;
    * a failed Connection Complete event is never inserted;
    * a Disconnection Complete event removes the handle;
    * handle reuse replaces the old entry and records the replacement;
    * target resolution raises on ambiguity instead of choosing arbitrarily.
    """

    def __init__(
        self,
        *,
        clock_ns=monotonic_ns,
    ) -> None:
        self._clock_ns = clock_ns
        self._lock = RLock()
        self._connections: dict[int, LEConnection] = {}

    def add(self, connection: LEConnection) -> None:
        """
        Add or replace an active connection.

        This method validates the handle, address, and address type.
        """

        _validate_handle(connection.handle)
        normalized_address = normalize_bd_addr(
            connection.peer_address
        )
        _validate_address_type(connection.peer_address_type)

        normalized = replace(
            connection,
            peer_address=normalized_address,
        )

        with self._lock:
            self._connections[normalized.handle] = normalized

    def remove(
        self,
        handle: int,
        *,
        ignore_unknown: bool = False,
    ) -> LEConnection | None:
        """
        Remove a connection by handle.

        Returns the removed connection, or ``None`` when
        ``ignore_unknown=True`` and the handle is absent.
        """

        _validate_handle(handle)

        with self._lock:
            removed = self._connections.pop(handle, None)

        if removed is None and not ignore_unknown:
            raise UnknownConnectionError(
                f"unknown connection handle 0x{handle:03x}"
            )

        return removed

    def get(self, handle: int) -> LEConnection | None:
        """Return a connection by handle, or ``None`` if absent."""

        _validate_handle(handle)

        with self._lock:
            return self._connections.get(handle)

    def require_handle(self, handle: int) -> LEConnection:
        """Return a connection by handle or raise ``UnknownConnectionError``."""

        connection = self.get(handle)

        if connection is None:
            raise UnknownConnectionError(
                f"unknown or inactive connection handle "
                f"0x{handle:03x}"
            )

        return connection

    def all(self) -> tuple[LEConnection, ...]:
        """Return all active connections as a stable tuple."""

        with self._lock:
            return tuple(
                sorted(
                    self._connections.values(),
                    key=lambda item: item.handle,
                )
            )

    def snapshot(self) -> ConnectionSnapshot:
        """Return an immutable registry snapshot."""

        return ConnectionSnapshot(
            connections=self.all()
        )

    def clear(self) -> None:
        """Remove all active connections."""

        with self._lock:
            self._connections.clear()

    def find(
        self,
        *,
        peer_address: str | None = None,
        peer_address_type: int | None = None,
    ) -> tuple[LEConnection, ...]:
        """
        Find active connections matching the supplied identity.

        An empty filter would match every active connection and is therefore
        rejected. Use ``all()`` when all connections are required.
        """

        if peer_address is None and peer_address_type is None:
            raise ValueError(
                "at least peer_address or peer_address_type "
                "must be supplied"
            )

        if peer_address is not None:
            peer_address = normalize_bd_addr(peer_address)

        if peer_address_type is not None:
            _validate_address_type(peer_address_type)

        with self._lock:
            return tuple(
                connection
                for connection in self._connections.values()
                if connection.matches(
                    peer_address=peer_address,
                    peer_address_type=peer_address_type,
                )
            )

    def require_target(
        self,
        *,
        peer_address: str,
        peer_address_type: int | None = None,
    ) -> LEConnection:
        """
        Resolve exactly one active connection for an authorized target.

        This method never chooses arbitrarily when multiple connections match.
        """

        matches = self.find(
            peer_address=peer_address,
            peer_address_type=peer_address_type,
        )

        if not matches:
            type_suffix = ""
            if peer_address_type is not None:
                type_suffix = (
                    f", address_type={peer_address_type}"
                )

            raise ConnectionAuthorizationError(
                "no active connection matches target "
                f"{normalize_bd_addr(peer_address)}"
                f"{type_suffix}"
            )

        if len(matches) > 1:
            handles = ", ".join(
                connection.handle_hex
                for connection in matches
            )

            raise AmbiguousConnectionError(
                "target matches multiple active connection handles: "
                f"{handles}"
            )

        return matches[0]

    def require_authorized_handle(
        self,
        handle: int,
        *,
        peer_address: str,
        peer_address_type: int | None = None,
    ) -> LEConnection:
        """
        Verify that a handle is active and belongs to the target.

        This is the preferred check immediately before any packet-building
        or packet-sending operation.
        """

        connection = self.require_handle(handle)

        if not connection.matches(
            peer_address=peer_address,
            peer_address_type=peer_address_type,
        ):
            raise ConnectionAuthorizationError(
                f"handle {connection.handle_hex} belongs to "
                f"{connection.peer_address}/"
                f"{connection.peer_address_type_name}, not the "
                f"authorized target "
                f"{normalize_bd_addr(peer_address)}"
            )

        return connection

    def process_event(
        self,
        event: object,
        *,
        timestamp_ns: int | None = None,
    ) -> LEConnection | None:
        """
        Update registry state from a parsed HCI event.

        Supported events:

        * LEConnectionComplete
        * LEEnhancedConnectionComplete
        * DisconnectionComplete
        * generic HCIEvent containing an LE Meta Event is not accepted;
          parse it first with ``parse_known_hci_event``.

        Returns:

        * the inserted connection for a successful connection event;
        * the removed connection for a disconnection event;
        * ``None`` for unrelated events or failed connection attempts.
        """

        event_time = (
            self._clock_ns()
            if timestamp_ns is None
            else timestamp_ns
        )

        if isinstance(event, LEConnectionComplete):
            return self._process_legacy_connection(
                event,
                timestamp_ns=event_time,
            )

        if isinstance(
            event,
            LEEnhancedConnectionComplete,
        ):
            return self._process_enhanced_connection(
                event,
                timestamp_ns=event_time,
            )

        if isinstance(event, DisconnectionComplete):
            return self.remove(
                event.connection_handle,
                ignore_unknown=True,
            )

        if isinstance(
            event,
            (
                HCIEvent,
                LEMetaEvent,
                CommandComplete,
                CommandStatus,
            ),
        ):
            return None

        raise TypeError(
            "unsupported event type: "
            f"{type(event)!r}; pass the result of "
            "parse_known_hci_event()"
        )

    def process_raw_event(
        self,
        raw: bytes | bytearray | memoryview,
        *,
        has_h4: bool = True,
        strict: bool = True,
        timestamp_ns: int | None = None,
    ) -> object:
        """
        Parse one raw HCI event and update the registry.

        Returns the parsed event object.
        """

        event = parse_known_hci_event(
            raw,
            has_h4=has_h4,
            strict=strict,
        )

        self.process_event(
            event,
            timestamp_ns=timestamp_ns,
        )

        return event

    def _process_legacy_connection(
        self,
        event: LEConnectionComplete,
        *,
        timestamp_ns: int,
    ) -> LEConnection | None:
        if not event.succeeded:
            return None

        connection = LEConnection(
            handle=event.connection_handle,
            role=event.role,
            peer_address=event.peer_address,
            peer_address_type=event.peer_address_type,
            connected_at_ns=timestamp_ns,
            source_event="le_connection_complete",
            connection_interval=event.connection_interval,
            peripheral_latency=event.peripheral_latency,
            supervision_timeout=event.supervision_timeout,
            central_clock_accuracy=(
                event.central_clock_accuracy
            ),
        )

        self.add(connection)
        return connection

    def _process_enhanced_connection(
        self,
        event: LEEnhancedConnectionComplete,
        *,
        timestamp_ns: int,
    ) -> LEConnection | None:
        if not event.succeeded:
            return None

        connection = LEConnection(
            handle=event.connection_handle,
            role=event.role,
            peer_address=event.peer_address,
            peer_address_type=event.peer_address_type,
            connected_at_ns=timestamp_ns,
            source_event=(
                "le_enhanced_connection_complete"
            ),
            connection_interval=event.connection_interval,
            peripheral_latency=event.peripheral_latency,
            supervision_timeout=event.supervision_timeout,
            central_clock_accuracy=(
                event.central_clock_accuracy
            ),
            local_resolvable_private_address=(
                event.local_resolvable_private_address
            ),
            peer_resolvable_private_address=(
                event.peer_resolvable_private_address
            ),
        )

        self.add(connection)
        return connection


def connection_to_dict(
    connection: LEConnection,
) -> dict[str, object]:
    """Convert a connection to a JSON-serialisable dictionary."""

    result: dict[str, object] = {
        "connection_handle": connection.handle,
        "connection_handle_hex": connection.handle_hex,
        "role": connection.role,
        "peer_address": connection.peer_address,
        "peer_address_type": connection.peer_address_type,
        "peer_address_type_name": (
            connection.peer_address_type_name
        ),
        "connected_at_ns": connection.connected_at_ns,
        "source_event": connection.source_event,
    }

    optional_fields = {
        "connection_interval": connection.connection_interval,
        "peripheral_latency": connection.peripheral_latency,
        "supervision_timeout": connection.supervision_timeout,
        "central_clock_accuracy": (
            connection.central_clock_accuracy
        ),
        "local_resolvable_private_address": (
            connection.local_resolvable_private_address
        ),
        "peer_resolvable_private_address": (
            connection.peer_resolvable_private_address
        ),
    }

    for key, value in optional_fields.items():
        if value is not None:
            result[key] = value

    return result


def normalize_bd_addr(address: str) -> str:
    """
    Normalize a Bluetooth address.

    Accepted examples:

        AA:BB:CC:DD:EE:FF
        aa-bb-cc-dd-ee-ff
        aabbccddeeff

    Returned form:

        AA:BB:CC:DD:EE:FF
    """

    if not isinstance(address, str):
        raise TypeError("Bluetooth address must be a string")

    compact = (
        address.replace(":", "")
        .replace("-", "")
        .replace(" ", "")
        .strip()
    )

    if len(compact) != 12:
        raise ValueError(
            "Bluetooth address must contain 6 octets"
        )

    try:
        raw = bytes.fromhex(compact)
    except ValueError as exc:
        raise ValueError(
            f"invalid Bluetooth address: {address!r}"
        ) from exc

    return format_bd_addr(raw)


def _validate_handle(handle: int) -> None:
    if isinstance(handle, bool) or not isinstance(handle, int):
        raise TypeError(
            "connection handle must be an integer"
        )

    if handle < 0 or handle > MAX_CONNECTION_HANDLE:
        raise ValueError(
            "connection handle must be between 0 and "
            f"0x{MAX_CONNECTION_HANDLE:03x}"
        )


def _validate_address_type(address_type: int) -> None:
    if isinstance(address_type, bool) or not isinstance(
        address_type,
        int,
    ):
        raise TypeError(
            "peer address type must be an integer"
        )

    if address_type < 0 or address_type > 0xFF:
        raise ValueError(
            "peer address type must be between 0 and 255"
        )


__all__ = [
    "AmbiguousConnectionError",
    "ConnectionAuthorizationError",
    "ConnectionRegistry",
    "ConnectionRegistryError",
    "ConnectionSnapshot",
    "ConnectionStateError",
    "LEConnection",
    "MAX_CONNECTION_HANDLE",
    "UnknownConnectionError",
    "connection_to_dict",
    "normalize_bd_addr",
]
