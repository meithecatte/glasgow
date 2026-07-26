import sys
import argparse
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


__all__ = ["LPCAnalyzerOverflow", "LPCAnalyzerApplet"]


class LPCAnalyzerOverflow(GlasgowAppletError):
    pass


class LPCAnalyzerFrontend(wiring.Component):
    stream: Out(stream.Signature(data.StructLayout({
        "data": 8,
        "start": 1,
    })))
    overflow: Out(1)

    def __init__(self, ports):
        self._ports = ports

        super().__init__()

    def elaborate(self, platform):
        m = Module()

        m.submodules.lclk_buffer   = lclk_buffer   = io.Buffer("i", self._ports.lclk)
        m.submodules.lframe_buffer = lframe_buffer = io.Buffer("i", self._ports.lframe)
        m.submodules.lad_buffer    = lad_buffer    = io.Buffer("i", self._ports.lad)

        if platform is not None:
            # With some margin above the spec value of 33 MHz
            platform.add_clock_constraint(lclk_buffer.i, 40e6)

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

        # Overflow handling
        overflow_lpc = Signal()
        with m.If(fifo.i.valid & ~fifo.i.ready):
            m.d.lpc += overflow_lpc.eq(1)

        overflow_sync = Signal()
        m.submodules.overflow_sync = cdc.FFSynchronizer(overflow_lpc, overflow_sync)
        with m.If(overflow_sync):
            m.d.sync += self.overflow.eq(1)

        # Actual LPC Protocol

        nibble = Signal(4)
        MAX_PRE_TAR = 5
        bytes_remaining = Signal(range(MAX_PRE_TAR))

        with m.FSM(domain="lpc"):
            with m.State("Idle"):
                with m.If(~lframe_buffer.i):
                    m.d.lpc += nibble.eq(lad_buffer.i)
                    m.next = "START"

            with m.State("START"):
                with m.If(~lframe_buffer.i):
                    m.d.lpc += nibble.eq(lad_buffer.i)
                with m.Else():
                    m.d.comb += fifo.i.p.data.eq(Cat(nibble, lad_buffer.i))
                    m.d.comb += fifo.i.p.start.eq(1)
                    m.d.comb += fifo.i.valid.eq(1)

                    with m.Switch(nibble):
                        with m.Case(START_TARGET):
                            cyctype = lad_buffer.i[2:3]
                            direction = lad_buffer.i[1]

                            # Number of bytes to capture before the TAR+SYNC
                            length_before_tar = Signal(range(MAX_PRE_TAR + 1))
                            with m.Switch(cyctype):
                                with m.Case(CYCTYPE_IO):
                                    with m.If(direction == DIR_WRITE):
                                        m.d.comb += length_before_tar.eq(3)
                                    with m.Else():
                                        m.d.comb += length_before_tar.eq(2)

                                with m.Case(CYCTYPE_MEM):
                                    with m.If(direction == DIR_WRITE):
                                        m.d.comb += length_before_tar.eq(5)
                                    with m.Else():
                                        m.d.comb += length_before_tar.eq(4)

                                with m.Default():
                                    m.d.comb += length_before_tar.eq(0)

                            with m.If(length_before_tar == 0):
                                m.next = "Idle"
                            with m.Else():
                                m.d.lpc += bytes_remaining.eq(length_before_tar - 1)
                                m.next = "nib1"

                        with m.Default():
                            m.next = "Idle"

            with m.State("nib1"):
                m.d.lpc += nibble.eq(lad_buffer.i)
                m.next = "nib2"

            with m.State("nib2"):
                m.d.comb += fifo.i.p.data.eq(Cat(lad_buffer.i, nibble))
                m.d.comb += fifo.i.valid.eq(1)

                with m.If(bytes_remaining == 0):
                    m.next = "Idle"
                with m.Else():
                    m.d.lpc += bytes_remaining.eq(bytes_remaining - 1)
                    m.next = "nib1"

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
