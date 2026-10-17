package com.reconx.sentinel.feature.netdiscovery

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class PortModelTest {
    @Test fun `well known ports map to service labels`() {
        assertThat(WellKnownPorts.service(443)).isEqualTo("https")
        assertThat(WellKnownPorts.service(22)).isEqualTo("ssh")
        assertThat(WellKnownPorts.service(12345)).isNull()
    }
    @Test fun `profiles expose explicit port sets`() {
        assertThat(ScanProfile.WEB.ports).contains(443)
        assertThat(ScanProfile.TOP_FULL.ports).hasSize(1024)
        assertThat(ScanProfile.COMMON.ports).doesNotContain(0)
    }
    @Test fun `open ports filter works`() {
        val r = HostScanResult("h","1.2.3.4", listOf(
            PortResult("h",80,PortState.OPEN,5,"http"),
            PortResult("h",81,PortState.CLOSED,null,null)), true)
        assertThat(r.openPorts).hasSize(1)
    }
}
