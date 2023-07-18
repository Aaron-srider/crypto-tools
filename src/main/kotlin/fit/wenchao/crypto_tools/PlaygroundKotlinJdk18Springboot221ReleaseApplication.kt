package fit.wenchao.crypto_tools

import mu.KotlinLogging
import org.springframework.boot.CommandLineRunner
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.stereotype.Component

@SpringBootApplication
class PlaygroundKotlinJdk18Springboot221ReleaseApplication

fun main(args: Array<String>) {
	runApplication<PlaygroundKotlinJdk18Springboot221ReleaseApplication>(*args)
}

@Component
class TestRunner: CommandLineRunner {

	private val log = KotlinLogging.logger {}

	override fun run(vararg args: String?) {
		log.info { "write some here" }

	}

}

