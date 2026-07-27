# Ref: Intel® Low Pin Count (LPC) Interface Specification
# Document Number: 251289-001
# Accession: G00019

import sys
import argparse
from contextlib import contextmanager
from amaranth import *
from amaranth.lib import data, wiring, stream, io, cdc
from amaranth.lib.wiring import Out

from glasgow.support import logging
from glasgow.support.logging import dump_hex
from glasgow.gateware.stream import AsyncQueue
from glasgow.gateware import cobs
from glasgow.abstract import AbstractAssembly, GlasgowPin
from glasgow.applet import GlasgowAppletError, GlasgowAppletV2
from glasgow.arch.lpc import *


__all__ = ["LPCAnalyzerOverflow", "LPCAnalyzerComponent", "LPCAnalyzerApplet"]


class LPCAnalyzerOverflow(GlasgowAppletError):
    pass


# The protocol between the gateware and the software is based on COBS-encoded packets.
# Each packet corresponds to one transaction, which we consider to start every time
# LFRAME is strobed. This means, that if a transaction gets aborted, the packet describing
# the actual transaction will be cut short, and we will transmit the abort itself
# as a separate packet.
#
# As the packet data is being generated live while the transaction is being received,
# the structure of the packets closely follows the protocol as seen on-the-wires.
# Whenever the contents of a byte directly come from nibbles transmitted on the LPC bus,
# the more-significant nibble contains the part that came first. Effectively, any addresses
# contained within the transactions get transmitted as plain-old big endian, while data
# bytes need to have their nibbles swapped.

# The first byte of each packet consists of the value of the START field, and the nibble
# immediately following it. For the implemented transaction types, that nibble is
# the CYCTYPE+DIR field.
class PacketHeader(data.Struct):
    nibble2:    4
    start:      Start

# If a transaction type is unrecognized, only that initial byte is transmitted.
# Otherwise, all the actual content of the transaction gets transcribed as is,
# with a byte of metadata inserted whenever the bus gets turned around.
#
# While a turnaround doesn't itself get encoded in any way, the SYNC that
# follows gets encoded into a byte which records the final value of the SYNC
# field, as well as the number of waitstates that occurred before it.
class SyncByte(data.Struct):
    # The values of this enum (except for Reserved) are assigned to match
    # the low two bits of the corresponding Sync value.
    class Kind(data.Enum):
        Ready       = 0b00
        ReadyMore   = 0b01
        # Device indicates error condition, data nevertheless follows.
        Error       = 0b10
        # Reserved value, usually caused by the device not responding at all.
        Reserved    = 0b11

        def from_sync(sync: Sync) -> Kind:
            return \
                Mux(sync == Sync.Ready,     SyncByte.Kind.Ready,
                Mux(sync == Sync.ReadyMore, SyncByte.Kind.ReadyMore,
                Mux(sync == Sync.Error,     SyncByte.Kind.Error,
                    SyncByte.Kind.Reserved)))

    wait: 6
    kind: Kind

# High-level structure:
#
# The LPCAnalyzerFrontend is driven by the LPC clock, and encodes the bus transactions
# into the packet format described above. This is then consumed by LPCAnalyzerComponent,
# which runs in the main sync clock domain, and drives the COBS encoder.

class LPCAnalyzerFrontend(wiring.Component):
    stream: Out(stream.Signature(data.StructLayout({
        "data": 8,
        "start": 1,
    })))

    # Asserted if the backpressure on `stream` causes an overflow. Once asserted,
    # this signal stays high.
    overflow: Out(1)

    # Asserted when the bus is idle, to indicate that the transaction is complete
    # and the next payload sent over the `stream` will have the `start` bit set.
    idle: Out(1)

    def __init__(self, ports):
        self._ports = ports

        super().__init__()

    def elaborate(self, platform):
        m = Module()

        m.submodules.lclk_buffer   = lclk_buffer   = io.Buffer("i", self._ports.lclk)
        m.submodules.lframe_buffer = lframe_buffer = io.Buffer("i", self._ports.lframe)
        m.submodules.lad_buffer    = lad_buffer    = io.Buffer("i", self._ports.lad)

        if platform is not None:
            platform.add_clock_constraint(lclk_buffer.i, 33e6)

        m.domains.lpc = cd_lpc = ClockDomain(clk_edge="neg", local=True)
        m.d.comb += cd_lpc.clk.eq(lclk_buffer.i)

        # Queue setup
        m.submodules.fifo = fifo = AsyncQueue(
            shape=self.stream.p.shape(),
            depth=4, # CDC only, no buffering
            i_domain="lpc",
            o_domain="sync"
        )
        wiring.connect(m, wiring.flipped(self.stream), fifo.o)

        # Actual LPC Protocol
        nibble = Signal(4)
        MAX_PRE_TAR = 5
        bytes_remaining = Signal(range(MAX_PRE_TAR))
        wait_states = Signal(6)
        cur_dir = Signal(Dir)

        # To handle aborts, LFRAME being low is handled homogenously across
        # all states of the FSM.
        #
        # Note that if an abort occurs in place of the second nibble of a byte,
        # the first nibble of said byte will effectively get discarded. This
        # shouldn't be a problem in practice, because aborts happen for a
        # reason, and the first nibble of a byte ain't one.
        @contextmanager
        def lframe_high_and_state(name):
            with m.State(name):
                with m.If(~lframe_buffer.i):
                    m.d.lpc += nibble.eq(lad_buffer.i)
                    m.next = "START"
                with m.Else():
                    yield

        with m.FSM(domain="lpc") as fsm:
            with lframe_high_and_state("Idle"):
                pass

            with lframe_high_and_state("START"):
                start = Start(nibble)

                header = PacketHeader(fifo.i.p.data)
                m.d.comb += header.start.eq(start)
                m.d.comb += header.nibble2.eq(lad_buffer.i)
                m.d.comb += fifo.i.p.start.eq(1)
                m.d.comb += fifo.i.valid.eq(1)

                with m.Switch(start):
                    with m.Case(Start.Target):
                        cyc = CyctypeDir(lad_buffer.i)

                        # Number of bytes to capture before the TAR+SYNC
                        length = Signal(range(MAX_PRE_TAR + 1))
                        with m.Switch(cyc.type):
                            with m.Case(Cyctype.IO):
                                with m.If(cyc.dir == Dir.Write):
                                    m.d.comb += length.eq(3)
                                with m.Else():
                                    m.d.comb += length.eq(2)

                            with m.Case(Cyctype.Mem):
                                with m.If(cyc.dir == Dir.Write):
                                    m.d.comb += length.eq(5)
                                with m.Else():
                                    m.d.comb += length.eq(4)

                            with m.Default():
                                # Unimplemented, go back to idle
                                m.d.comb += length.eq(0)

                        with m.If(length == 0):
                            m.next = "Idle"
                        with m.Else():
                            m.d.lpc += bytes_remaining.eq(length - 1)
                            m.d.lpc += cur_dir.eq(cyc.dir)
                            m.next = "nib1"

                    with m.Default():
                        m.next = "Idle"

            with lframe_high_and_state("nib1"):
                m.d.lpc += nibble.eq(lad_buffer.i)
                m.next = "nib2"

            with lframe_high_and_state("nib2"):
                m.d.comb += fifo.i.p.data.eq(Cat(lad_buffer.i, nibble))
                m.d.comb += fifo.i.valid.eq(1)

                with m.If(bytes_remaining == 0):
                    m.next = "TAR1"
                with m.Else():
                    m.d.lpc += bytes_remaining.eq(bytes_remaining - 1)
                    m.next = "nib1"

            with lframe_high_and_state("TAR1"):
                m.next = "TAR2"
            with lframe_high_and_state("TAR2"):
                m.next = "SYNC"
                m.d.lpc += wait_states.eq(0)

            with lframe_high_and_state("SYNC"):
                sync = Sync(lad_buffer.i)
                with m.Switch(Sync(lad_buffer.i)):
                    with m.Case(Sync.ShortWait, Sync.LongWait):
                        # Saturate the counter
                        with m.If(~wait_states.all()):
                            m.d.lpc += wait_states.eq(wait_states + 1)

                    with m.Case(Sync.Ready, Sync.ReadyMore, Sync.Error):
                        sb = SyncByte(fifo.i.p.data)
                        m.d.comb += sb.kind.eq(SyncByte.Kind.from_sync(sync))
                        m.d.comb += sb.wait.eq(wait_states)
                        m.d.comb += fifo.i.valid.eq(1)

                        with m.If(cur_dir == Dir.Read):
                            m.next = "resp1"
                        with m.Else():
                            m.next = "Idle"

                    with m.Default():
                        # Indicate protocol error
                        sb = SyncByte(fifo.i.p.data)
                        m.d.comb += sb.kind.eq(SyncByte.Kind.Reserved)
                        m.d.comb += sb.wait.eq(wait_states)
                        m.d.comb += fifo.i.valid.eq(1)
                        m.next = "Idle"

            with lframe_high_and_state("resp1"):
                m.d.lpc += nibble.eq(lad_buffer.i)
                m.next = "resp2"

            with lframe_high_and_state("resp2"):
                m.d.comb += fifo.i.p.data.eq(Cat(lad_buffer.i, nibble))
                m.d.comb += fifo.i.valid.eq(1)
                m.next = "Idle"

        # Overflow handling
        overflow_lpc = Signal()
        with m.If(fifo.i.valid & ~fifo.i.ready):
            m.d.lpc += overflow_lpc.eq(1)

        overflow_sync = Signal()
        m.submodules.overflow_sync = cdc.FFSynchronizer(overflow_lpc, overflow_sync)
        with m.If(overflow_sync):
            m.d.sync += self.overflow.eq(1)

        # Idle indication
        m.submodules.idle_sync = cdc.FFSynchronizer(fsm.ongoing("Idle"), self.idle)
        return m


class LPCAnalyzerComponent(wiring.Component):
    o_stream: Out(stream.Signature(8))
    overflow: Out(1)

    def __init__(self, ports, buffer_size: int):
        self._ports = ports
        self._buffer_size = buffer_size

        super().__init__()

    def elaborate(self, platform):
        m = Module()

        m.submodules.encoder  = encoder  = cobs.Encoder(fifo_depth=self._buffer_size)
        wiring.connect(m, wiring.flipped(self.o_stream), encoder.o)

        m.submodules.frontend = frontend = LPCAnalyzerFrontend(self._ports)

        with m.FSM():
            with m.State("Initial"):
                with m.If(frontend.stream.valid):
                    m.d.comb += encoder.i.p.data.eq(frontend.stream.p.data)
                    m.d.comb += encoder.i.valid.eq(1)
                    with m.If(encoder.i.ready):
                        m.d.comb += frontend.stream.ready.eq(1)
                        m.next = "Cont"

            with m.State("Cont"):
                with m.If(frontend.stream.valid):
                    with m.If(frontend.stream.p.start):
                        m.d.comb += encoder.i.p.end.eq(1)
                        m.d.comb += encoder.i.valid.eq(1)
                        with m.If(encoder.i.ready):
                            m.next = "Initial"
                    with m.Else():
                        m.d.comb += encoder.i.p.data.eq(frontend.stream.p.data)
                        m.d.comb += encoder.i.valid.eq(1)
                        with m.If(encoder.i.ready):
                            m.d.comb += frontend.stream.ready.eq(1)
                with m.Elif(frontend.idle):
                    m.d.comb += encoder.i.p.end.eq(1)
                    m.d.comb += encoder.i.valid.eq(1)
                    with m.If(encoder.i.ready):
                        m.next = "Initial"

        m.d.comb += self.overflow.eq(frontend.overflow)
        return m

class LPCAnalyzerInterface:
    def __init__(self, logger: logging.Logger, assembly: AbstractAssembly, *,
                 lclk: GlasgowPin, lframe: GlasgowPin, lad: GlasgowPin,
                 buffer_size=512):
        self._logger = logger
        self._level  = logging.DEBUG if self._logger.name == __name__ else logging.TRACE

        ports = assembly.add_port_group(lclk=lclk, lframe=lframe, lad=lad)
        component = assembly.add_submodule(LPCAnalyzerComponent(ports, buffer_size))

        # Don't use an interface FIFO; the input buffering is done in the COBS encoder.
        self._pipe = assembly.add_in_pipe(component.o_stream, fifo_depth=0)
        self._overflow = assembly.add_ro_register(component.overflow)

    def _log(self, message, *args):
        self._logger.log(self._level, "LPC analyzer: " + message, *args)

    async def capture(self) -> int:
        if await self._overflow:
            raise LPCAnalyzerOverflow("overflow")

        packet = cobs.decode((await self._pipe.recv_until(b"\0"))[:-1])
        self._log("capture %s", dump_hex(packet))
        return packet

class LPCAnalyzerApplet(GlasgowAppletV2):
    logger = logging.getLogger(__name__)
    help = "analyze LPC transactions"
    description = """
    Capture transactions on the LPC bus.

    Signal integrity is exceptionally important for this applet. When using
    flywires, twist every signal wire with a ground wire connected to ground at
    both ends, otherwise the captured data will likely be nonsense
    (alternatively, twist the LCLK wire with one ground wire, and all the other
    signals with another, shared ground wire).
    """
    # TODO: analyze required revision

    @classmethod
    def add_build_arguments(cls, parser, access):
        access.add_voltage_argument(parser)
        access.add_pins_argument(parser, "lclk",   required=True, default=True)
        access.add_pins_argument(parser, "lframe", required=True, default=True)
        access.add_pins_argument(parser, "lad",    required=True, default=True, width=4)
        parser.add_argument(
"--buffer-size", metavar="BYTES", type=int, default=16384,
            help="set FPGA trace buffer size to BYTES (must be power of 2, default: %(default)s)")

    def build(self, args):
        with self.assembly.add_applet(self):
            self.assembly.use_voltage(args.voltage)
            self.lpc_analyzer_iface = LPCAnalyzerInterface(self.logger, self.assembly,
                lclk=args.lclk, lframe=args.lframe, lad=args.lad,
                buffer_size=args.buffer_size)

    @classmethod
    def add_run_arguments(cls, parser):
        parser.add_argument("file", metavar="FILE",
            type=argparse.FileType("w"), nargs="?", default=sys.stdout,
            help="save communications to FILE as pairs of hex sequences")

    async def run(self, args):
        try:
            args.file.truncate()
        except OSError:
            pass # pipe, tty/pty, etc

        while True:
            packet = await self.lpc_analyzer_iface.capture()
            args.file.write(f"{packet.hex()}\n")
            args.file.flush()
