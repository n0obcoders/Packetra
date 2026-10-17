package com.reconx.sentinel.feature.recon

import com.reconx.sentinel.core.common.Outcome

/**
 * Passive email-authentication posture check (spec §7 "email security"): reads
 * SPF/DMARC/MX/DNSSEC via DoH and reports configuration gaps. Purely a defensive
 * configuration review of public DNS records — it sends no mail and enumerates
 * no mailboxes.
 */
class EmailSecurity(private val doh: DohResolver) {
    data class Check(val name: String, val ok: Boolean, val detail: String)

    suspend fun assess(domain: String): Outcome<List<Check>> {
        val out = mutableListOf<Check>()

        val txt = doh.query(domain, "TXT")
        val txtValues = (txt as? Outcome.Ok)?.value?.Answer.orEmpty().mapNotNull { it.data?.trim('"') }
        val spf = txtValues.firstOrNull { it.startsWith("v=spf1", true) }
        out += when {
            spf == null -> Check("SPF", false, "No v=spf1 record — domain can be spoofed.")
            spf.contains("+all") -> Check("SPF", false, "SPF ends in +all (permits any sender).")
            spf.contains("~all") || spf.contains("-all") ->
                Check("SPF", true, "SPF present (${if (spf.contains("-all")) "-all hardfail" else "~all softfail"}).")
            else -> Check("SPF", false, "SPF present but no all mechanism — incomplete.")
        }

        val dmarcTxt = doh.query("_dmarc.$domain", "TXT")
        val dmarc = (dmarcTxt as? Outcome.Ok)?.value?.Answer.orEmpty()
            .mapNotNull { it.data?.trim('"') }.firstOrNull { it.startsWith("v=DMARC1", true) }
        out += when {
            dmarc == null -> Check("DMARC", false, "No _dmarc record — no reporting/enforcement policy.")
            dmarc.contains("p=none") -> Check("DMARC", false, "DMARC p=none (monitor only, not enforcing).")
            dmarc.contains("p=reject") -> Check("DMARC", true, "DMARC p=reject (enforcing).")
            dmarc.contains("p=quarantine") -> Check("DMARC", true, "DMARC p=quarantine (enforcing).")
            else -> Check("DMARC", false, "DMARC present but policy unclear.")
        }

        // DKIM: probe a small set of common selectors passively (a DNS TXT lookup,
        // never any mail). Presence of any v=DKIM1 key is reported; absence is only
        // a hint because selectors are arbitrary and we cannot enumerate them all.
        val dkimSelectors = listOf("default", "google", "selector1", "selector2", "k1", "dkim", "mail", "s1", "s2")
        var dkimFound: String? = null
        for (sel in dkimSelectors) {
            val rec = doh.query("$sel._domainkey.$domain", "TXT")
            val v = (rec as? Outcome.Ok)?.value?.Answer.orEmpty()
                .mapNotNull { it.data?.trim('"') }
                .firstOrNull { it.contains("v=DKIM1", true) || it.contains("k=rsa", true) || it.contains("p=", true) }
            if (v != null) { dkimFound = sel; break }
        }
        out += if (dkimFound != null)
            Check("DKIM", true, "DKIM key published at selector '$dkimFound._domainkey'.")
        else
            Check("DKIM", false, "No DKIM key on common selectors (${dkimSelectors.take(4).joinToString()}…); " +
                "mail may be unsigned, or a custom selector is in use — verify with the mail provider.")

        val mx = doh.query(domain, "MX")
        val mxCount = (mx as? Outcome.Ok)?.value?.Answer.orEmpty().size
        out += Check("MX", mxCount > 0, if (mxCount > 0) "$mxCount mail exchanger(s)." else "No MX records.")

        val soa = doh.query(domain, "SOA")
        val dnssec = (soa as? Outcome.Ok)?.value?.AD == true ||
            (txt as? Outcome.Ok)?.value?.AD == true
        out += Check("DNSSEC", dnssec, if (dnssec) "Responses are DNSSEC-authenticated." else "No DNSSEC authentication observed.")

        return Outcome.Ok(out)
    }
}
