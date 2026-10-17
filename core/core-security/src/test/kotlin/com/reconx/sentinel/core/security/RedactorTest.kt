package com.reconx.sentinel.core.security

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class RedactorTest {
    @Test fun `bearer token redacted`() {
        val out = Redactor.redact("Authorization: Bearer abc.def.ghi")
        assertThat(out).doesNotContain("abc.def.ghi")
        assertThat(out).contains("<redacted-token>")
    }
    @Test fun `password field redacted`() {
        assertThat(Redactor.redact("""{"password":"hunter2"}""")).doesNotContain("hunter2")
    }
    @Test fun `jwt redacted`() {
        val jwt = "eyJhbGciOiJIUzI1NiІ9.eyJzdWIiOiIxIn0.sig".replace("І", "I")
        assertThat(Redactor.redact("token=$jwt")).doesNotContain(jwt)
    }
    @Test fun `describeSecret never echoes value`() {
        assertThat(Redactor.describeSecret("hunter2")).isEqualTo("<set:7 chars>")
        assertThat(Redactor.describeSecret("")).isEqualTo("<empty>")
    }
}
