package com.reconx.sentinel.feature.authaudit

/**
 * Controls for the ONLY automated credential path this module allows:
 * verifying a single operator-supplied TEST credential against a local or
 * explicitly-authorized test environment (spec §10 "Safe execution controls").
 *
 * These are hard caps enforced before any check runs. There is no multi-account,
 * no password list, and no rotation/evasion. A real password is never logged;
 * only a redacted descriptor is retained.
 */
data class TestAccountPolicy(
    val requireLocalOrAuthorizedTestEnv: Boolean = true,
    val maxAttempts: Int = 3,            // conservative, per spec
    val maxTestAccounts: Int = 1,
    val requestsPerSecond: Double = 0.5,
    val maxDurationSeconds: Int = 60,
    val requireExplicitAuthorizationProfile: Boolean = true,
) {
    init {
        require(maxAttempts in 1..5) { "maxAttempts must be 1..5 (controlled test only)" }
        require(maxTestAccounts in 1..3) { "maxTestAccounts must be 1..3" }
        require(requestsPerSecond <= 1.0) { "requestsPerSecond capped at 1.0 for auth tests" }
    }
}

/** Describes what WILL run, for the pre-execution authorization confirmation UI. */
data class AuthTestPlan(
    val targetEnvironment: String,
    val isLocalOrAuthorizedTestEnv: Boolean,
    val authorizationProfileId: String?,
    val policy: TestAccountPolicy = TestAccountPolicy(),
) {
    fun blockingReasons(): List<String> = buildList {
        if (policy.requireLocalOrAuthorizedTestEnv && !isLocalOrAuthorizedTestEnv)
            add("target is not marked as a local or explicitly-authorized test environment")
        if (policy.requireExplicitAuthorizationProfile && authorizationProfileId.isNullOrBlank())
            add("no explicit authorization profile is attached")
    }
    val permitted: Boolean get() = blockingReasons().isEmpty()
}
