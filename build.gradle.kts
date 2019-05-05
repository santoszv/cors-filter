import org.jetbrains.dokka.gradle.DokkaTask
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.3.31"
    id("org.jetbrains.dokka") version "0.9.18"
    `java-library`
    `maven-publish`
    signing
}

repositories {
    mavenCentral()
    jcenter()
}

dependencies {
    implementation(kotlin("stdlib-jdk8"))

    compileOnly("javax:javaee-api:8.0")

    testImplementation("org.junit.jupiter:junit-jupiter:5.4.0")
    testImplementation("org.mockito:mockito-core:2.24.5")
    testImplementation("javax:javaee-api:7.0")
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
}

tasks.withType<Test> {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

tasks.withType<DokkaTask> {
    moduleName = "CORS Filter"
    outputFormat = "javadoc"
    outputDirectory = "$buildDir/dokka/javadoc"
    includes = listOf("module.md", "packages.md")
    jdkVersion = 8
}

tasks.register<Jar>("javadocJar") {
    archiveClassifier.set("javadoc")
    from("$buildDir/dokka/javadoc")
    dependsOn("dokka")
}

tasks.register<Jar>("sourcesJar") {
    archiveClassifier.set("sources")
    val sourceSet = sourceSets.main.get()
    from(sourceSet.allSource)
}

publishing {
    publications {
        create<MavenPublication>("CORSFilter") {

            groupId = "${properties["CORSFilter.GroupID"]}"
            artifactId = "${properties["CORSFilter.ArtifactID"]}"
            version = "${properties["CORSFilter.Version"]}"

            from(components["java"])
            artifact(tasks["sourcesJar"])
            artifact(tasks["javadocJar"])

            pom {
                name.set("Cross-Origin Resource Sharing (CORS) Web Filter")
                description.set("Cross-Origin Resource Sharing (CORS) Web Filter")
                url.set("https://github.com/santoszv/cors-filter")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                }
                developers {
                    developer {
                        id.set("https://github.com/santoszv")
                        name.set("Santos Zatarain Vera")
                        email.set("coder.santoszv@gmail.com")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/santoszv/cors-filter.git")
                    developerConnection.set("scm:git:https://github.com/santoszv/cors-filter.git")
                    url.set("https://github.com/santoszv/cors-filter")
                }
            }
        }
    }

    repositories {
        val isSnapshot = "${properties["CORSFilter.Version"]}".endsWith("-SNAPSHOT")
        val isUpload = "${properties["OSSRH.Upload"]}".toBoolean()
        val username = "${properties["OSSRH.Username"]}"
        val password = "${properties["OSSRH.Password"]}"
        if (isUpload) {
            maven {
                url = if (isSnapshot)
                    uri("https://oss.sonatype.org/content/repositories/snapshots/")
                else
                    uri("https://oss.sonatype.org/service/local/staging/deploy/maven2/")
                credentials {
                    if (username.isNotBlank()) {
                        this.username = username
                    }
                    if (password.isNotBlank()) {
                        this.password = password
                    }
                }
            }
        } else {
            mavenLocal()
        }
    }
}

signing {
    useGpgCmd()
    val keyName = properties["signing.gnupg.keyName"] as? String
    if (!keyName.isNullOrBlank()) {
        sign(publishing.publications["CORSFilter"])
    }
}

afterEvaluate {
    tasks.withType<AbstractPublishToMaven> {
        dependsOn("build")
    }
}