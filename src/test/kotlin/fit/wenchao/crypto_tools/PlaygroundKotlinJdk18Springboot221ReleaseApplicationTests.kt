package fit.wenchao.crypto_tools

import cn.hutool.core.lang.Holder
import fit.wenchao.crypto_tools.utils.ByteUtils
import fit.wenchao.crypto_tools.utils.ByteUtils.*
import mu.KotlinLogging
import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest

@SpringBootTest
class PlaygroundKotlinJdk18Springboot221ReleaseApplicationTests {

    @Test
    fun contextLoads() {
    }

}

enum class InputType {
    BASE64,
    HEX,
    RAW
}


class BytesTab {
    private val log = KotlinLogging.logger {}

    class OutputResult {
        var base64: String? = null;
        var hex: String? = null;
        var raw: String? = null;
    }

    fun renderToView(outputResult: OutputResult) {
        log.debug { "base64: ${outputResult.base64}" }
        log.debug { "hex: ${outputResult.hex}" }
        log.debug { "raw: ${outputResult.raw}" }
    }

    fun inputToBox(userInput: String, inputType: InputType): OutputResult {
        val outputResult = OutputResult()
        when (inputType) {
            InputType.BASE64 -> {
                outputResult.base64 = userInput
                val origin = fromBase64(userInput)
                outputResult.hex = ByteUtils.hex(origin)
                outputResult.raw = ByteUtils.raw(origin)
            }

            InputType.HEX -> {
                outputResult.hex = userInput
                val origin = fromHex(userInput)
                outputResult.base64 = ByteUtils.base64(origin)
                outputResult.raw = ByteUtils.raw(origin)
            }

            InputType.RAW -> {
                outputResult.raw = userInput
                val origin = fromRaw(userInput)
                outputResult.base64 = ByteUtils.base64(origin)
                outputResult.hex = ByteUtils.hex(origin)
            }
        }
        return outputResult
    }

    fun action(userInput: String, inputType: InputType) {
        // pass in the hex format of certificate
        var outputResult: OutputResult = inputToBox(userInput, inputType);
        renderToView(outputResult)
    }

    @Test
    fun bytesTab() {
        var bytes = "IjC2el9NxNQxBGYKJTvMQH79rlLR9i0UJJ8zMgUBAvzoUhriGI+MMBOhHVO3tKk2lGUmwUqckexAiFbrkug6qw=="
        action(bytes, InputType.BASE64)
        // pub key from agent database
        // 2230b67a5f4dc4d43104660a253bcc407efdae52d1f62d14249f3332050102fce8521ae2188f8c3013a11d53b7b4a936946526c14a9c91ec408856eb92e83aab


        bytes = "304f2d69108e3f7800079724a84c03c98620cbafacf8c6f4cd6dd5314ae3fb5ad1bc78a5b57af748eff031b45d1d7a223ebc3a2222960499eee7791c42ae9889"
        action(bytes, InputType.HEX)
        // pub key used to enc random a, which should from the kms enc cert, originated from kms system key
        // 16:25:16.692 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.BytesTab - base64: ME8taRCOP3gAB5ckqEwDyYYgy6+s+Mb0zW3VMUrj+1rRvHiltXr3SO/wMbRdHXoiPrw6IiKWBJnu53kcQq6YiQ==
        // 16:25:16.692 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.BytesTab - hex: 304f2d69108e3f7800079724a84c03c98620cbafacf8c6f4cd6dd5314ae3fb5ad1bc78a5b57af748eff031b45d1d7a223ebc3a2222960499eee7791c42ae9889
        // 16:25:16.692 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.BytesTab - raw: [48, 79, 45, 105, 16, -114, 63, 120, 0, 7, -105, 36, -88, 76, 3, -55, -122, 32, -53, -81, -84, -8, -58, -12, -51, 109, -43, 49, 74, -29, -5, 90, -47, -68, 120, -91, -75, 122, -9, 72, -17, -16, 49, -76, 93, 29, 122, 34, 62, -68, 58, 34, 34, -106, 4, -103, -18, -25, 121, 28, 66, -82, -104, -119]

        bytes = "6c05492613965969f3b617e18a381a329d8ebda58d776dce8c3caaf5ddc803142e56dc51c7a7decf54bdeeba67d7de6c9b176b342bf7b9b0c17e2374a06ebe71"
        action(bytes, InputType.HEX)
        // pub key for the pri key to dec random a, which should from the kms dec cert, originated from kms system key
        // 16:26:28.348 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.BytesTab - base64: bAVJJhOWWWnzthfhijgaMp2OvaWNd23OjDyq9d3IAxQuVtxRx6fez1S97rpn195smxdrNCv3ubDBfiN0oG6+cQ==
        // 16:26:28.348 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.BytesTab - hex: 6c05492613965969f3b617e18a381a329d8ebda58d776dce8c3caaf5ddc803142e56dc51c7a7decf54bdeeba67d7de6c9b176b342bf7b9b0c17e2374a06ebe71
        // 16:26:28.348 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.BytesTab - raw: [108, 5, 73, 38, 19, -106, 89, 105, -13, -74, 23, -31, -118, 56, 26, 50, -99, -114, -67, -91, -115, 119, 109, -50, -116, 60, -86, -11, -35, -56, 3, 20, 46, 86, -36, 81, -57, -89, -34, -49, 84, -67, -18, -70, 103, -41, -34, 108, -101, 23, 107, 52, 43, -9, -71, -80, -63, 126, 35, 116, -96, 110, -66, 113]

        bytes = "e135b6e7ed0db9a29228bc0f88b2fafd1bad4ec6fcc403bcf37ec62e314c6719"
        action(bytes, InputType.HEX)
        // pri key to dec random a
        // 16:27:19.522 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.BytesTab - base64: 4TW25+0NuaKSKLwPiLL6/RutTsb8xAO8837GLjFMZxk=
        // 16:27:19.522 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.BytesTab - hex: e135b6e7ed0db9a29228bc0f88b2fafd1bad4ec6fcc403bcf37ec62e314c6719
        // 16:27:19.522 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.BytesTab - raw: [-31, 53, -74, -25, -19, 13, -71, -94, -110, 40, -68, 15, -120, -78, -6, -3, 27, -83, 78, -58, -4, -60, 3, -68, -13, 126, -58, 46, 49, 76, 103, 25]
    }
}


class CertTab {
    private val log = KotlinLogging.logger {}

    class OutputResult {
        var base64: String? = null;
        var hex: String? = null;
        var raw: String? = null;
        var origin: ByteArray? = null;
    }

    fun renderCertToView(outputResult: OutputResult) {
        log.debug { "cert base64: ${outputResult.base64}" }
        log.debug { "cert hex: ${outputResult.hex}" }
        log.debug { "cert raw: ${outputResult.raw}" }
    }

    fun renderPublicKeyToView(outputResult: OutputResult) {
        log.debug { "pub key base64: ${outputResult.base64}" }
        log.debug { "pub key hex: ${outputResult.hex}" }
        log.debug { "pub key raw: ${outputResult.raw}" }
    }

    fun inputToBox(
        userInput: String,
        inputType: InputType,
        certOutputResultHolder: Holder<OutputResult>,
        publicKeyOutputResultHolder: Holder<OutputResult>,
    ) {
        val certOutputResult = OutputResult()
        val publicKeyOutputResult = OutputResult()
        when (inputType) {
            InputType.BASE64 -> {
                certOutputResult.base64 = userInput
                certOutputResult.origin = fromBase64(userInput)
                certOutputResult.hex = ByteUtils.hex(certOutputResult.origin)
                certOutputResult.raw = ByteUtils.raw(certOutputResult.origin)
            }

            InputType.HEX -> {
                certOutputResult.hex = userInput
                certOutputResult.origin = fromHex(userInput)
                certOutputResult.base64 = ByteUtils.base64(certOutputResult.origin)
                certOutputResult.raw = ByteUtils.raw(certOutputResult.origin)
            }

            InputType.RAW -> {
                certOutputResult.raw = userInput
                certOutputResult.origin = fromRaw(userInput)
                certOutputResult.base64 = ByteUtils.base64(certOutputResult.origin)
                certOutputResult.hex = ByteUtils.hex(certOutputResult.origin)
            }
        }

        val x509CertPkOrigin = CertUtil.getX509CertPk(certOutputResult.origin)
        publicKeyOutputResult.origin = x509CertPkOrigin
        publicKeyOutputResult.base64 = ByteUtils.base64(x509CertPkOrigin)
        publicKeyOutputResult.hex = ByteUtils.hex(x509CertPkOrigin)
        publicKeyOutputResult.raw = ByteUtils.raw(x509CertPkOrigin)
        certOutputResultHolder.set(certOutputResult)
        publicKeyOutputResultHolder.set(publicKeyOutputResult)
    }

    fun action(userInput: String, inputType: InputType) {
        // pass in the hex format of certificate
        var certOutputResultHolder: Holder<OutputResult> = Holder<OutputResult>()
        var publicKeyOutputResultHolder: Holder<OutputResult> = Holder<OutputResult>()
        inputToBox(userInput, inputType, certOutputResultHolder, publicKeyOutputResultHolder);
        renderCertToView(certOutputResultHolder.get())
        renderPublicKeyToView(publicKeyOutputResultHolder.get())
    }

    @Test
    fun certTab() {
        var cert =
            "MIIB6jCCAZCgAwIBAgIGAYlTsLfqMAoGCCqBHM9VAYN1MA4xDDAKBgNVBAoMA2NjbTAeFw0yMzA3MTQwOTE3MTdaFw0zMzA3MTQwOTE3MTdaMA4xDDAKBgNVBAoMA2NjbTCCATMwgewGByqGSM49AgEwgeACAQEwLAYHKoZIzj0BAQIhAP////7/////////////////////AAAAAP//////////MEQEIP////7/////////////////////AAAAAP/////////8BCAo6fqenZ9eNE1ankvPZQmn85eJ9RWrj5LdvL1BTZQOkwRBBDLEriwfGYEZX5kERmo5yZSP4wu/8mYL4XFaRYkzTHTHvDc2ovT2d5xZvc7ja2khU9Cph3zGKkdAAt8y5SE58KACIQD////+////////////////cgPfayHGBStTu/QJOdVBIwIBAQNCAASp9Ik5KyIxZgPu3eHAvK71d9pPxkfjPF05tT35Chk4/bYzC2vLHOEa1GG7AOS9wajrJs7uDewqlY7jWWVnYBc7MAoGCCqBHM9VAYN1A0gAMEUCIQDxb7Xl51qB36jHrfDryqrdv0HmzTIKWRkRoU+8gcQwHwIgJ1Jd+uOsZAM3ICQ+7/IPKQe7IVtPqjJe3LGPDx9p9VA="
        action(cert, InputType.BASE64)
        // from kms database
        // 11:59:08.785 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.CertTab - cert base64: MIIB6jCCAZCgAwIBAgIGAYlTsLfqMAoGCCqBHM9VAYN1MA4xDDAKBgNVBAoMA2NjbTAeFw0yMzA3MTQwOTE3MTdaFw0zMzA3MTQwOTE3MTdaMA4xDDAKBgNVBAoMA2NjbTCCATMwgewGByqGSM49AgEwgeACAQEwLAYHKoZIzj0BAQIhAP////7/////////////////////AAAAAP//////////MEQEIP////7/////////////////////AAAAAP/////////8BCAo6fqenZ9eNE1ankvPZQmn85eJ9RWrj5LdvL1BTZQOkwRBBDLEriwfGYEZX5kERmo5yZSP4wu/8mYL4XFaRYkzTHTHvDc2ovT2d5xZvc7ja2khU9Cph3zGKkdAAt8y5SE58KACIQD////+////////////////cgPfayHGBStTu/QJOdVBIwIBAQNCAASp9Ik5KyIxZgPu3eHAvK71d9pPxkfjPF05tT35Chk4/bYzC2vLHOEa1GG7AOS9wajrJs7uDewqlY7jWWVnYBc7MAoGCCqBHM9VAYN1A0gAMEUCIQDxb7Xl51qB36jHrfDryqrdv0HmzTIKWRkRoU+8gcQwHwIgJ1Jd+uOsZAM3ICQ+7/IPKQe7IVtPqjJe3LGPDx9p9VA=
        // 11:59:08.787 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.CertTab - cert hex: 308201ea30820190a0030201020206018953b0b7ea300a06082a811ccf55018375300e310c300a060355040a0c0363636d301e170d3233303731343039313731375a170d3333303731343039313731375a300e310c300a060355040a0c0363636d308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff30440420fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc042028e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e9304410432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0022100fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d5412302010103420004a9f489392b22316603eedde1c0bcaef577da4fc647e33c5d39b53df90a1938fdb6330b6bcb1ce11ad461bb00e4bdc1a8eb26ceee0dec2a958ee359656760173b300a06082a811ccf550183750348003045022100f16fb5e5e75a81dfa8c7adf0ebcaaaddbf41e6cd320a591911a14fbc81c4301f022027525dfae3ac64033720243eeff20f2907bb215b4faa325edcb18f0f1f69f550
        // 11:59:08.788 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.CertTab - cert raw: [48, -126, 1, -22, 48, -126, 1, -112, -96, 3, 2, 1, 2, 2, 6, 1, -119, 83, -80, -73, -22, 48, 10, 6, 8, 42, -127, 28, -49, 85, 1, -125, 117, 48, 14, 49, 12, 48, 10, 6, 3, 85, 4, 10, 12, 3, 99, 99, 109, 48, 30, 23, 13, 50, 51, 48, 55, 49, 52, 48, 57, 49, 55, 49, 55, 90, 23, 13, 51, 51, 48, 55, 49, 52, 48, 57, 49, 55, 49, 55, 90, 48, 14, 49, 12, 48, 10, 6, 3, 85, 4, 10, 12, 3, 99, 99, 109, 48, -126, 1, 51, 48, -127, -20, 6, 7, 42, -122, 72, -50, 61, 2, 1, 48, -127, -32, 2, 1, 1, 48, 44, 6, 7, 42, -122, 72, -50, 61, 1, 1, 2, 33, 0, -1, -1, -1, -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, 0, -1, -1, -1, -1, -1, -1, -1, -1, 48, 68, 4, 32, -1, -1, -1, -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, 0, -1, -1, -1, -1, -1, -1, -1, -4, 4, 32, 40, -23, -6, -98, -99, -97, 94, 52, 77, 90, -98, 75, -49, 101, 9, -89, -13, -105, -119, -11, 21, -85, -113, -110, -35, -68, -67, 65, 77, -108, 14, -109, 4, 65, 4, 50, -60, -82, 44, 31, 25, -127, 25, 95, -103, 4, 70, 106, 57, -55, -108, -113, -29, 11, -65, -14, 102, 11, -31, 113, 90, 69, -119, 51, 76, 116, -57, -68, 55, 54, -94, -12, -10, 119, -100, 89, -67, -50, -29, 107, 105, 33, 83, -48, -87, -121, 124, -58, 42, 71, 64, 2, -33, 50, -27, 33, 57, -16, -96, 2, 33, 0, -1, -1, -1, -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 114, 3, -33, 107, 33, -58, 5, 43, 83, -69, -12, 9, 57, -43, 65, 35, 2, 1, 1, 3, 66, 0, 4, -87, -12, -119, 57, 43, 34, 49, 102, 3, -18, -35, -31, -64, -68, -82, -11, 119, -38, 79, -58, 71, -29, 60, 93, 57, -75, 61, -7, 10, 25, 56, -3, -74, 51, 11, 107, -53, 28, -31, 26, -44, 97, -69, 0, -28, -67, -63, -88, -21, 38, -50, -18, 13, -20, 42, -107, -114, -29, 89, 101, 103, 96, 23, 59, 48, 10, 6, 8, 42, -127, 28, -49, 85, 1, -125, 117, 3, 72, 0, 48, 69, 2, 33, 0, -15, 111, -75, -27, -25, 90, -127, -33, -88, -57, -83, -16, -21, -54, -86, -35, -65, 65, -26, -51, 50, 10, 89, 25, 17, -95, 79, -68, -127, -60, 48, 31, 2, 32, 39, 82, 93, -6, -29, -84, 100, 3, 55, 32, 36, 62, -17, -14, 15, 41, 7, -69, 33, 91, 79, -86, 50, 94, -36, -79, -113, 15, 31, 105, -11, 80]
        // 11:59:08.788 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.CertTab - pub key base64: qfSJOSsiMWYD7t3hwLyu9XfaT8ZH4zxdObU9+QoZOP22MwtryxzhGtRhuwDkvcGo6ybO7g3sKpWO41llZ2AXOw==
        // 11:59:08.788 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.CertTab - pub key hex: a9f489392b22316603eedde1c0bcaef577da4fc647e33c5d39b53df90a1938fdb6330b6bcb1ce11ad461bb00e4bdc1a8eb26ceee0dec2a958ee359656760173b
        // 11:59:08.788 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.CertTab - pub key raw: [-87, -12, -119, 57, 43, 34, 49, 102, 3, -18, -35, -31, -64, -68, -82, -11, 119, -38, 79, -58, 71, -29, 60, 93, 57, -75, 61, -7, 10, 25, 56, -3, -74, 51, 11, 107, -53, 28, -31, 26, -44, 97, -69, 0, -28, -67, -63, -88, -21, 38, -50, -18, 13, -20, 42, -107, -114, -29, 89, 101, 103, 96, 23, 59]

        cert =
            "MIIB6jCCAZCgAwIBAgIGAYlh/9hIMAoGCCqBHM9VAYN1MA4xDDAKBgNVBAoMA2NjbTAeFw0yMzA3MTcwMzU4MjRaFw0zMzA3MTcwMzU4MjRaMA4xDDAKBgNVBAoMA2NjbTCCATMwgewGByqGSM49AgEwgeACAQEwLAYHKoZIzj0BAQIhAP////7/////////////////////AAAAAP//////////MEQEIP////7/////////////////////AAAAAP/////////8BCAo6fqenZ9eNE1ankvPZQmn85eJ9RWrj5LdvL1BTZQOkwRBBDLEriwfGYEZX5kERmo5yZSP4wu/8mYL4XFaRYkzTHTHvDc2ovT2d5xZvc7ja2khU9Cph3zGKkdAAt8y5SE58KACIQD////+////////////////cgPfayHGBStTu/QJOdVBIwIBAQNCAASp9Ik5KyIxZgPu3eHAvK71d9pPxkfjPF05tT35Chk4/bYzC2vLHOEa1GG7AOS9wajrJs7uDewqlY7jWWVnYBc7MAoGCCqBHM9VAYN1A0gAMEUCIQC5ta0qpFuN2iVa92fX7wdd6ZBjmzZz4jTbQrrQS0yv5AIgJa4HyLo4n8YdLRWvOVPTCJLI+ye+hej3UeQjck4nRyg="
        action(cert, InputType.BASE64)
        // from agent download
        // 11:59:08.789 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.CertTab - cert base64: MIIB6jCCAZCgAwIBAgIGAYlh/9hIMAoGCCqBHM9VAYN1MA4xDDAKBgNVBAoMA2NjbTAeFw0yMzA3MTcwMzU4MjRaFw0zMzA3MTcwMzU4MjRaMA4xDDAKBgNVBAoMA2NjbTCCATMwgewGByqGSM49AgEwgeACAQEwLAYHKoZIzj0BAQIhAP////7/////////////////////AAAAAP//////////MEQEIP////7/////////////////////AAAAAP/////////8BCAo6fqenZ9eNE1ankvPZQmn85eJ9RWrj5LdvL1BTZQOkwRBBDLEriwfGYEZX5kERmo5yZSP4wu/8mYL4XFaRYkzTHTHvDc2ovT2d5xZvc7ja2khU9Cph3zGKkdAAt8y5SE58KACIQD////+////////////////cgPfayHGBStTu/QJOdVBIwIBAQNCAASp9Ik5KyIxZgPu3eHAvK71d9pPxkfjPF05tT35Chk4/bYzC2vLHOEa1GG7AOS9wajrJs7uDewqlY7jWWVnYBc7MAoGCCqBHM9VAYN1A0gAMEUCIQC5ta0qpFuN2iVa92fX7wdd6ZBjmzZz4jTbQrrQS0yv5AIgJa4HyLo4n8YdLRWvOVPTCJLI+ye+hej3UeQjck4nRyg=
        // 11:59:08.789 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.CertTab - cert hex: 308201ea30820190a0030201020206018961ffd848300a06082a811ccf55018375300e310c300a060355040a0c0363636d301e170d3233303731373033353832345a170d3333303731373033353832345a300e310c300a060355040a0c0363636d308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff30440420fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc042028e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e9304410432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0022100fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d5412302010103420004a9f489392b22316603eedde1c0bcaef577da4fc647e33c5d39b53df90a1938fdb6330b6bcb1ce11ad461bb00e4bdc1a8eb26ceee0dec2a958ee359656760173b300a06082a811ccf550183750348003045022100b9b5ad2aa45b8dda255af767d7ef075de990639b3673e234db42bad04b4cafe4022025ae07c8ba389fc61d2d15af3953d30892c8fb27be85e8f751e423724e274728
        // 11:59:08.789 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.CertTab - cert raw: [48, -126, 1, -22, 48, -126, 1, -112, -96, 3, 2, 1, 2, 2, 6, 1, -119, 97, -1, -40, 72, 48, 10, 6, 8, 42, -127, 28, -49, 85, 1, -125, 117, 48, 14, 49, 12, 48, 10, 6, 3, 85, 4, 10, 12, 3, 99, 99, 109, 48, 30, 23, 13, 50, 51, 48, 55, 49, 55, 48, 51, 53, 56, 50, 52, 90, 23, 13, 51, 51, 48, 55, 49, 55, 48, 51, 53, 56, 50, 52, 90, 48, 14, 49, 12, 48, 10, 6, 3, 85, 4, 10, 12, 3, 99, 99, 109, 48, -126, 1, 51, 48, -127, -20, 6, 7, 42, -122, 72, -50, 61, 2, 1, 48, -127, -32, 2, 1, 1, 48, 44, 6, 7, 42, -122, 72, -50, 61, 1, 1, 2, 33, 0, -1, -1, -1, -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, 0, -1, -1, -1, -1, -1, -1, -1, -1, 48, 68, 4, 32, -1, -1, -1, -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, 0, -1, -1, -1, -1, -1, -1, -1, -4, 4, 32, 40, -23, -6, -98, -99, -97, 94, 52, 77, 90, -98, 75, -49, 101, 9, -89, -13, -105, -119, -11, 21, -85, -113, -110, -35, -68, -67, 65, 77, -108, 14, -109, 4, 65, 4, 50, -60, -82, 44, 31, 25, -127, 25, 95, -103, 4, 70, 106, 57, -55, -108, -113, -29, 11, -65, -14, 102, 11, -31, 113, 90, 69, -119, 51, 76, 116, -57, -68, 55, 54, -94, -12, -10, 119, -100, 89, -67, -50, -29, 107, 105, 33, 83, -48, -87, -121, 124, -58, 42, 71, 64, 2, -33, 50, -27, 33, 57, -16, -96, 2, 33, 0, -1, -1, -1, -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 114, 3, -33, 107, 33, -58, 5, 43, 83, -69, -12, 9, 57, -43, 65, 35, 2, 1, 1, 3, 66, 0, 4, -87, -12, -119, 57, 43, 34, 49, 102, 3, -18, -35, -31, -64, -68, -82, -11, 119, -38, 79, -58, 71, -29, 60, 93, 57, -75, 61, -7, 10, 25, 56, -3, -74, 51, 11, 107, -53, 28, -31, 26, -44, 97, -69, 0, -28, -67, -63, -88, -21, 38, -50, -18, 13, -20, 42, -107, -114, -29, 89, 101, 103, 96, 23, 59, 48, 10, 6, 8, 42, -127, 28, -49, 85, 1, -125, 117, 3, 72, 0, 48, 69, 2, 33, 0, -71, -75, -83, 42, -92, 91, -115, -38, 37, 90, -9, 103, -41, -17, 7, 93, -23, -112, 99, -101, 54, 115, -30, 52, -37, 66, -70, -48, 75, 76, -81, -28, 2, 32, 37, -82, 7, -56, -70, 56, -97, -58, 29, 45, 21, -81, 57, 83, -45, 8, -110, -56, -5, 39, -66, -123, -24, -9, 81, -28, 35, 114, 78, 39, 71, 40]
        // 11:59:08.789 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.CertTab - pub key base64: qfSJOSsiMWYD7t3hwLyu9XfaT8ZH4zxdObU9+QoZOP22MwtryxzhGtRhuwDkvcGo6ybO7g3sKpWO41llZ2AXOw==
        // 11:59:08.789 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.CertTab - pub key hex: a9f489392b22316603eedde1c0bcaef577da4fc647e33c5d39b53df90a1938fdb6330b6bcb1ce11ad461bb00e4bdc1a8eb26ceee0dec2a958ee359656760173b
        // 11:59:08.789 [main] DEBUG com.example.playgroundkotlinjdk1_8springboot_2_2_1_release.CertTab - pub key raw: [-87, -12, -119, 57, 43, 34, 49, 102, 3, -18, -35, -31, -64, -68, -82, -11, 119, -38, 79, -58, 71, -29, 60, 93, 57, -75, 61, -7, 10, 25, 56, -3, -74, 51, 11, 107, -53, 28, -31, 26, -44, 97, -69, 0, -28, -67, -63, -88, -21, 38, -50, -18, 13, -20, 42, -107, -114, -29, 89, 101, 103, 96, 23, 59]


    }
}