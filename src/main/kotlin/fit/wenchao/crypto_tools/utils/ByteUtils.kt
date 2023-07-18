package fit.wenchao.crypto_tools.utils

import org.slf4j.LoggerFactory
import java.util.*

class ByteDecodeException(msg: String?, cause: Throwable?) : RuntimeException(msg, cause) {
    constructor() : this(null, null)
    constructor(msg: String?) : this(msg, null)
}

object ByteUtils {
    private val log = LoggerFactory.getLogger(ByteUtils::class.java)

    // region: hex
    fun hex(bytes: ByteArray): String {
        return cn.hutool.core.util.HexUtil.encodeHexStr(bytes)
    }

    fun fromHex(hex: String): ByteArray {
        try {
            return cn.hutool.core.util.HexUtil.decodeHex(hex)
        } catch (e: Exception) {
            throw ByteDecodeException("Invalid hexadecimal encoding", e)
        }
    }
    // endregion

    // region: log
    fun debug(prefix: String, bytes: ByteArray) {
        log.debug("$prefix: ${hex(bytes)}")
    }
    // endregion

    // region: base64
    fun base64(bytes: ByteArray): String {
        return Base64.getEncoder().encodeToString(bytes)
    }

    fun fromBase64(base64: String): ByteArray {
        try {
            return Base64.getDecoder().decode(base64)
        } catch (e: Exception) {
            throw ByteDecodeException("Invalid Base64 encoding", e)
        }

    }
    // endregion

    // region: raw
    fun raw(bytes: ByteArray): String {
        return bytes.contentToString()
    }

    fun fromRaw(raw: String): ByteArray {
        try {

            // Remove the square brackets and any whitespace from the input string
            val cleanInput: String = raw.replace(Regex("\\[|\\]|\\s"), "")

            // Split the comma-separated values
            val stringValues = cleanInput.split(",").toTypedArray()

            // Create a new byte array with the same length as the input values
            val byteArray = ByteArray(stringValues.size)

            // Parse each string value and store it in the byte array
            for (i in stringValues.indices) {
                byteArray[i] = stringValues[i].trim().toByte()
            }

            return byteArray
        } catch (e: Exception) {
            throw ByteDecodeException("Invalid raw encoding", e)
        }
    }
    // endregion
}


fun main() {
    var string = "[105, 166, 154, 105, 166, 154, 105, 166, 154, 105, 166, 154, 105, 166, 172, 105, 171, 44]"

    val fromRaw = ByteUtils.fromRaw(string)
    println(fromRaw)
}