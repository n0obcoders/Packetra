package com.reconx.sentinel.feature.capture

/**
 * Maps an ISO 3166-1 alpha-2 country code to a display name and flag emoji, so a
 * captured flow's offline geo lookup can be shown as a readable location
 * ("United States 🇺🇸") rather than a bare code. Pure/offline — no geolocation
 * service is contacted.
 */
object CountryNames {
    /** "US" -> "United States", unknown -> the code itself. */
    fun name(code: String?): String {
        if (code.isNullOrBlank()) return "—"
        return NAMES[code.uppercase()] ?: code.uppercase()
    }

    /** Regional-indicator flag emoji for a 2-letter code, or empty if not A–Z×2. */
    fun flag(code: String?): String {
        val c = code?.uppercase() ?: return ""
        if (c.length != 2 || c[0] !in 'A'..'Z' || c[1] !in 'A'..'Z') return ""
        val base = 0x1F1E6
        return String(Character.toChars(base + (c[0] - 'A'))) +
            String(Character.toChars(base + (c[1] - 'A')))
    }

    /** "United States 🇺🇸" (flag omitted if the code isn't a valid pair). */
    fun display(code: String?): String {
        if (code.isNullOrBlank()) return "—"
        val f = flag(code)
        return (name(code) + if (f.isNotEmpty()) " $f" else "")
    }

    private val NAMES = mapOf(
        "US" to "United States", "GB" to "United Kingdom", "IE" to "Ireland",
        "DE" to "Germany", "FR" to "France", "NL" to "Netherlands", "ES" to "Spain",
        "IT" to "Italy", "SE" to "Sweden", "NO" to "Norway", "FI" to "Finland",
        "DK" to "Denmark", "PL" to "Poland", "CH" to "Switzerland", "AT" to "Austria",
        "BE" to "Belgium", "PT" to "Portugal", "CZ" to "Czechia", "RO" to "Romania",
        "RU" to "Russia", "UA" to "Ukraine", "TR" to "Türkiye", "IN" to "India",
        "CN" to "China", "HK" to "Hong Kong", "TW" to "Taiwan", "JP" to "Japan",
        "KR" to "South Korea", "SG" to "Singapore", "MY" to "Malaysia", "ID" to "Indonesia",
        "TH" to "Thailand", "VN" to "Vietnam", "PH" to "Philippines", "AU" to "Australia",
        "NZ" to "New Zealand", "CA" to "Canada", "MX" to "Mexico", "BR" to "Brazil",
        "AR" to "Argentina", "CL" to "Chile", "CO" to "Colombia", "ZA" to "South Africa",
        "EG" to "Egypt", "NG" to "Nigeria", "KE" to "Kenya", "AE" to "United Arab Emirates",
        "SA" to "Saudi Arabia", "IL" to "Israel", "PK" to "Pakistan", "BD" to "Bangladesh",
        "LK" to "Sri Lanka", "NP" to "Nepal",
    )
}
