pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "Packetra"

include(":app")
include(":core:core-common")
include(":core:core-security")
include(":core:core-network")
include(":core:core-storage")
include(":feature:network-discovery")
include(":feature:reconnaissance")
include(":feature:web-assessment")
include(":feature:packet-capture")
include(":feature:auth-audit")
include(":feature:reporting")
