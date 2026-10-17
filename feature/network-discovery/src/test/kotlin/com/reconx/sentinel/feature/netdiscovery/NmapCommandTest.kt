package com.reconx.sentinel.feature.netdiscovery

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class NmapCommandTest {
    @Test fun `parses udp scan with ports and timing`() {
        val r = NmapCommand.parse("nmap -sU -p 53,123 -T4 example.com")
        assertThat(r.errors).isEmpty()
        assertThat(r.target).isEqualTo("example.com")
        assertThat(r.config!!.scanType).isEqualTo(ScanType.UDP)
        assertThat(r.config!!.ports).containsExactly(53, 123)
        assertThat(r.config!!.timing).isEqualTo(Timing.T4)
    }
    @Test fun `unsupported option is an explicit error`() {
        val r = NmapCommand.parse("-sS -p 80 host")
        assertThat(r.config).isNull()
        assertThat(r.errors.first()).contains("unsupported option '-sS'")
    }
    @Test fun `fast flag selects top 100 and sV enables detection`() {
        val r = NmapCommand.parse("-F -sV host")
        assertThat(r.config!!.ports).isEqualTo(PortSpec.TOP_100)
        assertThat(r.config!!.serviceDetection).isTrue()
    }
    @Test fun `Pn disables host discovery`() {
        val r = NmapCommand.parse("-Pn -p 80 host")
        assertThat(r.config!!.hostDiscovery).isFalse()
    }
}
