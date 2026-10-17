package com.reconx.sentinel.feature.capture

import com.google.common.truth.Truth.assertThat
import java.io.File
import org.junit.Test

class PcapngWriterTest {

    private fun u32le(b: ByteArray, off: Int): Long =
        (b[off].toLong() and 0xFF) or ((b[off + 1].toLong() and 0xFF) shl 8) or
            ((b[off + 2].toLong() and 0xFF) shl 16) or ((b[off + 3].toLong() and 0xFF) shl 24)

    @Test fun `writes a valid pcapng section header, interface and packet block`() {
        val f = File.createTempFile("cap", ".pcapng").apply { deleteOnExit() }
        val payload = byteArrayOf(0x45, 0x00, 0x00, 0x14, 0x01, 0x02) // 6 bytes (not 4-aligned)
        PcapngWriter(f).use { it.write(payload, payload.size); assertThat(it.packets).isEqualTo(1L) }

        val b = f.readBytes()
        // SHB
        assertThat(u32le(b, 0)).isEqualTo(0x0A0D0D0AL)       // SHB block type
        assertThat(u32le(b, 4)).isEqualTo(28L)               // SHB total length
        assertThat(u32le(b, 8)).isEqualTo(0x1A2B3C4DL)       // byte-order magic
        assertThat(u32le(b, 24)).isEqualTo(28L)              // SHB trailer length
        // IDB at offset 28
        assertThat(u32le(b, 28)).isEqualTo(0x00000001L)      // IDB block type
        assertThat(u32le(b, 32)).isEqualTo(20L)              // IDB total length
        assertThat((b[36].toInt() and 0xFF)).isEqualTo(101)  // linktype LINKTYPE_RAW
        // EPB at offset 48
        assertThat(u32le(b, 48)).isEqualTo(0x00000006L)      // EPB block type
        val epbTotal = u32le(b, 52)
        assertThat(epbTotal).isEqualTo((32 + 6 + 2).toLong()) // 6-byte payload padded to 8
        // EPB header: type(48) total(52) iface(56) ts_hi(60) ts_lo(64) caplen(68) origlen(72)
        assertThat(u32le(b, 68)).isEqualTo(6L)               // captured length
        assertThat(u32le(b, 72)).isEqualTo(6L)               // original length
        // trailing total length equals leading one
        assertThat(u32le(b, 48 + epbTotal.toInt() - 4)).isEqualTo(epbTotal)
    }
}
