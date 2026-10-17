package com.reconx.sentinel.feature.recon

/**
 * Fingerprints for subdomain-takeover detection. A subdomain whose CNAME points
 * at a third-party service that is NOT claimed/provisioned ("dangling" pointer)
 * can be taken over by anyone who registers that resource. This is PURELY a
 * detection table + matcher: it reads the CNAME target and the HTTP response the
 * service already serves, and matches the service's own "not found / unclaimed"
 * banner. It NEVER claims, registers or modifies the resource — it only flags
 * that the owner should re-point or remove the DNS record.
 */
object TakeoverRules {
    /**
     * @param service human name of the hosting provider.
     * @param cnamePatterns substrings that identify the service in a CNAME target.
     * @param fingerprints response-body/status markers the service serves for an
     *        UNCLAIMED resource — presence means the pointer is dangling.
     */
    data class Service(
        val service: String,
        val cnamePatterns: List<String>,
        val fingerprints: List<String>,
    )

    val all: List<Service> = listOf(
        Service("AWS S3", listOf("s3.amazonaws.com", "s3-website", ".s3.", "s3.dualstack"),
            listOf("NoSuchBucket", "The specified bucket does not exist")),
        Service("GitHub Pages", listOf("github.io", "github.map.fastly.net"),
            listOf("There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file")),
        Service("Heroku", listOf("herokuapp.com", "herokudns.com", "herokussl.com"),
            listOf("No such app", "herokucdn.com/error-pages/no-such-app.html")),
        Service("Microsoft Azure", listOf("azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net", "azureedge.net"),
            listOf("404 Web Site not found", "The resource you are looking for has been removed")),
        Service("Fastly", listOf("fastly.net"),
            listOf("Fastly error: unknown domain")),
        Service("Shopify", listOf("myshopify.com", "shops.myshopify.com"),
            listOf("Sorry, this shop is currently unavailable", "Only one step left!")),
        Service("Zendesk", listOf("zendesk.com"),
            listOf("Help Center Closed", "this help center no longer exists")),
        Service("Amazon CloudFront", listOf("cloudfront.net"),
            listOf("The request could not be satisfied", "ERROR: The request could not be satisfied")),
        Service("Pantheon", listOf("pantheonsite.io", "pantheon.io"),
            listOf("The gods are wise, but do not know of the site which you seek")),
        Service("Surge.sh", listOf("surge.sh"),
            listOf("project not found")),
        Service("Bitbucket", listOf("bitbucket.io"),
            listOf("Repository not found")),
        Service("Ghost", listOf("ghost.io"),
            listOf("The thing you were looking for is no longer here, or never was")),
        Service("Tumblr", listOf("domains.tumblr.com"),
            listOf("Whatever you were looking for doesn't currently exist at this address")),
        Service("Unbounce", listOf("unbouncepages.com"),
            listOf("The requested URL was not found on this server")),
        Service("Readme.io", listOf("readme.io"),
            listOf("Project doesnt exist... yet!")),
        Service("Netlify", listOf("netlify.app", "netlify.com"),
            listOf("Not Found - Request ID")),
    )

    /** The hosting service a CNAME target belongs to, or null. Case-insensitive. */
    fun serviceForCname(cname: String?): Service? {
        if (cname.isNullOrBlank()) return null
        val c = cname.trim().trimEnd('.').lowercase()
        return all.firstOrNull { svc -> svc.cnamePatterns.any { c.contains(it) } }
    }

    /** True if the response body carries the service's "unclaimed resource" banner. */
    fun hasDanglingFingerprint(svc: Service, body: String): Boolean =
        svc.fingerprints.any { body.contains(it, ignoreCase = true) }
}
