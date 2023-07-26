package fit.wenchao.crypto_tools.rest

import cn.hutool.core.date.DateField
import cn.hutool.core.date.DateTime
import cn.hutool.core.util.HexUtil
import com.alibaba.fastjson.JSONObject
import fit.wenchao.crypto_tools.CertUtil
import fit.wenchao.crypto_tools.JavaSecureKeyPairToBytesConversionUtils
import fit.wenchao.crypto_tools.Sm2Util
import fit.wenchao.crypto_tools.exception.GlobalExceptionHandler
import fit.wenchao.crypto_tools.utils.ByteDecodeException
import fit.wenchao.crypto_tools.utils.ByteUtils
import mu.KotlinLogging
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.validation.annotation.Validated
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.io.UnsupportedEncodingException
import java.math.BigInteger
import java.net.URLDecoder
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.*
import javax.validation.Valid
import javax.validation.constraints.NotEmpty
import javax.validation.constraints.NotNull


enum class InputType {
    BASE64,
    HEX,
    RAW,
    UNKNOWN
}

fun decideInputType(userInput: String): InputType {
    if (userInput.startsWith("[") && userInput.endsWith("]")) {
        return InputType.RAW
    }

    try {
        Base64.getDecoder().decode(userInput)
        return InputType.BASE64
    } catch (e: Exception) {

    }

    val hexChars = "0123456789ABCDEFabcdef"
    // Check if the input string is a valid hexadecimal encoding
    if (userInput.length % 2 == 0 && userInput.all { it in hexChars }) {
        return InputType.HEX
    }

    return InputType.UNKNOWN
}

class ResultVO {
    var type: String? = null
    var base64: String? = null
    var hex: String? = null
    var byteArray: String? = null
    var charArray: String? = null
    var bytesSquare: String? = null
}

@RestController
@Validated
@RequestMapping("/api")
class Controller {

    private val log = KotlinLogging.logger {}

    @GetMapping("/bytes-format-translation")
    fun bytesFormatTranslation(@NotEmpty userInput: String?, @NotEmpty userInputMode: String?): Any {

        var userInputDecoded = ""
        try {
            userInputDecoded = URLDecoder.decode(userInput, "UTF-8")
        } catch (e: UnsupportedEncodingException) {
            throw GlobalExceptionHandler.ApiException(HttpStatus.BAD_REQUEST, "request param invalid")
        }

        var modeMap = mutableMapOf(
            "base64" to { InputType.BASE64 },
            "hex" to { InputType.HEX },
            "byteArray" to { InputType.RAW },
            "auto" to { decideInputType(userInput!!) },
        )


        var inputType = modeMap[userInputMode!!]?.let { it() }
            ?: modeMap["auto"]!!()

        val outputResult = ResultVO()
        outputResult.type = inputType.name
        var originBytes: ByteArray? = null
        try {
            when (inputType) {
                InputType.BASE64 -> {
                    outputResult.base64 = userInputDecoded
                    val origin = ByteUtils.fromBase64(userInputDecoded)
                    outputResult.hex = ByteUtils.hex(origin)
                    outputResult.byteArray = ByteUtils.raw(origin)
                    originBytes = origin
                }

                InputType.HEX -> {
                    outputResult.hex = userInputDecoded
                    val origin = ByteUtils.fromHex(userInputDecoded)
                    outputResult.base64 = ByteUtils.base64(origin)
                    outputResult.byteArray = ByteUtils.raw(origin)
                    originBytes = origin
                }

                InputType.RAW -> {
                    outputResult.byteArray = userInputDecoded
                    val origin = ByteUtils.fromRaw(userInputDecoded)
                    outputResult.base64 = ByteUtils.base64(origin)
                    outputResult.hex = ByteUtils.hex(origin)
                    originBytes = origin
                }

                else -> {
                    originBytes = null
                    outputResult.byteArray = null
                    outputResult.base64 = null
                    outputResult.hex = null
                }
            }
        } catch (e: ByteDecodeException) {
            throw GlobalExceptionHandler.ApiException(HttpStatus.BAD_REQUEST, "request param invalid")
        }


        var unsignedByteList = mutableListOf<Int>()
        outputResult.byteArray?.let {
            traverseEach(it) { aJavaByte ->
                unsignedByteList.add(aJavaByte.toInt() and 0xff)
            }
        }
        outputResult.charArray = unsignedByteList.joinToString(
            separator = ", ",
            prefix = "[",
            postfix = "]"
        )

        originBytes?.let {
            outputResult.bytesSquare = byteArrayToBinarySquare(it.toList())
        } ?: run {
            outputResult.bytesSquare = null
        }

        return outputResult
    }


    @GetMapping("/cert")
    fun cert(@NotNull @Valid pubKeyBase64: String ): ResponseEntity<Any> {
        var pubKey: ByteArray
        try {
            pubKey = Base64.getDecoder().decode(pubKeyBase64)
        }catch (e: Exception) {
            throw GlobalExceptionHandler.ApiException(HttpStatus.BAD_REQUEST, "must be base64")
        }


        val bytesToPublicKey = JavaSecureKeyPairToBytesConversionUtils.publickey(pubKey);

        val generateKeyPair = Sm2Util.generateKeyPair()
        val bytesToPrivateKey = JavaSecureKeyPairToBytesConversionUtils.privatekey(generateKeyPair.privateKey)


        val begin = DateTime.now().toJdkDate()
        val end = DateTime.now().offset(DateField.YEAR, 10).toJdkDate()
        var encCert: ByteArray? = generateX509CertificateBytes(
            bytesToPublicKey,
            bytesToPrivateKey,
            X500Name(BCStyle.INSTANCE, "o=ccm"),
            X500Name(BCStyle.INSTANCE, "o=ccm"),
            begin,
            end
        )

        encCert?:return ResponseEntity(JSONObject.toJSONString("can not generate cert"), HttpStatus.BAD_REQUEST)

        return ResponseEntity(JSONObject.toJSONString(HexUtil.encodeHex(encCert)), HttpStatus.OK);
    }
}

fun generateX509CertificateBytes(
    publicKey: PublicKey?,
    privateKey: PrivateKey?,
    subject: X500Name?,
    issuer: X500Name?,
    startDate: Date?,
    endDate: Date?,
): ByteArray {
    return try {
        generateX509Certificate(publicKey, privateKey, subject, issuer, startDate, endDate).encoded
    } catch (e: java.lang.Exception) {
        throw RuntimeException("Failed to generate X509 certificate", e)
    }
}

fun generateX509Certificate(
    publicKey: PublicKey?,
    privateKey: PrivateKey?,
    subject: X500Name?,
    issuer: X500Name?,
    startDate: Date?,
    endDate: Date?,
): X509Certificate {
    return try {
        val serial = BigInteger.valueOf(System.currentTimeMillis())
        val certBuilder: X509v3CertificateBuilder =
            JcaX509v3CertificateBuilder(issuer, serial, startDate, endDate, subject, publicKey)

        // Sign the certificate using the private key
        val contentSigner =
            JcaContentSignerBuilder("SM3WITHSM2").setProvider("BC").build(privateKey)
        val certHolder = certBuilder.build(contentSigner)

        // Convert the certificate holder to X509Certificate
        JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder)
    } catch (e: java.lang.Exception) {
        throw RuntimeException("Failed to generate X509 certificate", e)
    }
}



fun traverseEach(input: String, action: (Byte) -> Unit) {
    val elements = input
        .removeSurrounding("[", "]") // Remove square brackets
        .split(",") // Split by comma and space

    for (element in elements) {
        val byteValue = element.trim().toByte()
        action(byteValue)
    }
}

fun byteArrayToBinarySquare(byteList: List<Byte>): String {
    val sb = StringBuilder()
    var oneLineByteCount = 2

    for (i in byteList.indices step oneLineByteCount) {
        var list = mutableListOf<Byte>()
        // get oneLineByteCount count bytes
        for (j in i until i + oneLineByteCount) {
            val orNull = byteList.getOrNull(j)
            orNull?.let {
                list.add(orNull)
            }
        }
        list.forEach {
            sb.append(byteToString(it))
            sb.append(" ")
        }
        sb.dropLast(1)
        sb.append("\n")

    }
    sb.dropLast(1)
    return sb.toString()
}

fun byteToString(byteValue: Byte): String {
    var stringBuilder = StringBuilder()
    var low8Value = byteValue.toInt() and 0xff
    for (i in 0 until 8) {
        val lastBit = low8Value and 1
        low8Value = low8Value shr 1
        stringBuilder.append(lastBit)
    }
    return stringBuilder.reverse().toString()
}