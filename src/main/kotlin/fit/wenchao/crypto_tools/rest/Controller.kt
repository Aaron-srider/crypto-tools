package fit.wenchao.crypto_tools.rest

import fit.wenchao.crypto_tools.exception.BackendException
import fit.wenchao.crypto_tools.exception.RespCode
import fit.wenchao.crypto_tools.utils.ByteDecodeException
import fit.wenchao.crypto_tools.utils.ByteUtils
import mu.KotlinLogging
import org.springframework.validation.annotation.Validated
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.io.UnsupportedEncodingException
import java.net.URLDecoder
import java.util.*
import javax.validation.constraints.NotEmpty


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
            throw BackendException(null, RespCode.FRONT_END_PARAMS_ERROR)
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
            throw BackendException(null, RespCode.INVALID_ENCODED_STRING)
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