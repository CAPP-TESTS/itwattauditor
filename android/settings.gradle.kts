pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // HMS Core SDKs (Safety Detect SysIntegrity for the Huawei devices without GMS)
        maven("https://developer.huawei.com/repo/") {
            content { includeGroupByRegex("com\\.huawei\\..*") }
        }
    }
}
rootProject.name = "itwattauditor"
include(":app")
