package fit.wenchao.crypto_tools.exception

import com.alibaba.fastjson.JSONObject
import fit.wenchao.crypto_tools.utils.ClassUtils
import mu.KotlinLogging
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.HttpMessageNotReadableException
import org.springframework.validation.BindException
import org.springframework.validation.BindingResult
import org.springframework.validation.FieldError
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.MissingServletRequestParameterException
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.ResponseBody
import org.springframework.web.multipart.MaxUploadSizeExceededException
import org.springframework.web.multipart.support.MissingServletRequestPartException
import javax.servlet.http.HttpServletResponse
import javax.validation.ConstraintViolationException
import javax.validation.Path

enum class ErrorCode {
    UNKNOWN,
    SUCCESS,
    INVALID_PARAMETER,
    UPLOAD_FILE_SIZE_EXCEED_UPPER_LIMIT,
    SERVER_ERROR,
    KEY_NOT_EXISTS
}


/**
 * 全局异常处理类
 */
@ControllerAdvice
class GlobalExceptionHandler {

    private val log = KotlinLogging.logger {}


    class ParameterCheckResult {
        var paramCheckMap: JSONObject = JSONObject()
        fun putResult(field: String, message: String?) {
            paramCheckMap.put(field, message)
        }
    }

    class ApiException : RuntimeException {
        var httpStatus: HttpStatus
        var msg: Any?

        constructor(httpStatus: HttpStatus, msg: Any?) {
            this.httpStatus = httpStatus
            this.msg = msg
        }

        constructor(message: String?, httpStatus: HttpStatus, msg: Any?) : super(message) {
            this.httpStatus = httpStatus
            this.msg = msg
        }

        constructor(message: String?, cause: Throwable?, httpStatus: HttpStatus, msg: Any?) : super(message, cause) {
            this.httpStatus = httpStatus
            this.msg = msg
        }

        override fun toString(): String {
            return "ApiException{" +
                    "httpStatus=" + httpStatus +
                    ", msg=" + msg +
                    '}'
        }
    }

    // @Value("\${spring.servlet.multipart.max-file-size}")
    var uploadLimit: String? = null

    // region: error code handler
    @ExceptionHandler(ApiException::class)
    @ResponseBody
    fun errorCodeException(req: HttpServletResponse, ex: ApiException): ResponseEntity<*> {
       log.error("[{}] {}", ex.httpStatus, ex.msg)
        return turnBackendExceptionIntoJsonResult(req, ex)
    }

    /**
     * @param ex the exception
     * @return the json result
     */
    private fun turnBackendExceptionIntoJsonResult(req: HttpServletResponse, ex: ApiException): ResponseEntity<*> {
        return ResponseEntity<Any?>(JSONObject.toJSONString(ex.msg), ex.httpStatus)
    }

    // endregion
    // region: validation error
    @ExceptionHandler(
        BindException::class,
        MethodArgumentNotValidException::class
    )
    @ResponseBody
    fun paramValidateException(ex: Exception?): JsonResult {
        return try {
            val bindingResult: BindingResult = ClassUtils.getFieldValue(ex!!, "bindingResult", BindingResult::class.java)
                ?: return JsonResult(ErrorCode.INVALID_PARAMETER, null)
            val parameterCheckResult = extractValidationErrorEntries(bindingResult)
            val jsonResult = JsonResult(ErrorCode.INVALID_PARAMETER, parameterCheckResult)
            log.error("Error:{}", jsonResult)
            jsonResult
        } catch (e: NoSuchFieldException) {
            JsonResult(ErrorCode.INVALID_PARAMETER, null)
        }
    }

    @ExceptionHandler(ConstraintViolationException::class)
    @ResponseBody
    fun constraintViolationException(ex: ConstraintViolationException): ResponseEntity<*> {
        val constraintViolations = ex.constraintViolations
        val parameterCheckResult = ParameterCheckResult()
        for (constraintViolation in constraintViolations) {
            parameterCheckResult.putResult(
                getLastPathNode(constraintViolation.propertyPath),
                constraintViolation.message
            )
        }
        return ResponseEntity<Any?>(parameterCheckResult, HttpStatus.BAD_REQUEST)
    }

    private fun extractValidationErrorEntries(bindingResult: BindingResult): ParameterCheckResult {
        val parameterCheckResult = ParameterCheckResult()
        for (objectError in bindingResult.allErrors) {
            val fieldError = objectError as FieldError
            parameterCheckResult.putResult(fieldError.field, fieldError.defaultMessage)
        }
        return parameterCheckResult
    }

    // endregion
    // region: other exception
    @ExceptionHandler(Exception::class)
    @ResponseBody
    fun otherException(req: HttpServletResponse, ex: Exception): ResponseEntity<*> {
        log.error(
            "Server Exception-Name:{}，Server Exception-Msg:{}",
            ex.javaClass.typeName,
            ex.message
        )
        if (ex is HttpMessageNotReadableException) {
            return turnBackendExceptionIntoJsonResult(
                req,
                ApiException(HttpStatus.BAD_REQUEST, "Request paramater is invalid")
            )
        }
        if (ex is MissingServletRequestParameterException) {
            return turnBackendExceptionIntoJsonResult(
                req,
                ApiException(HttpStatus.BAD_REQUEST, "Required request body is missing")
            )
        }
        if (ex is MaxUploadSizeExceededException) {
            return turnBackendExceptionIntoJsonResult(
                req, ApiException(
                    HttpStatus.PAYLOAD_TOO_LARGE,
                    "Limitation: $uploadLimit"
                )
            )
        }
        if (ex is MissingServletRequestPartException) {
            return turnBackendExceptionIntoJsonResult(req, ApiException(HttpStatus.BAD_REQUEST, ex.message))
        }
        ex.printStackTrace()
        return turnBackendExceptionIntoJsonResult(req, ApiException(HttpStatus.INTERNAL_SERVER_ERROR, ex.message))
    } // endregion

    companion object {
        private fun getLastPathNode(path: Path): String {
            val wholePath = path.toString()
            val i = wholePath.lastIndexOf(".")
            return if (i != -1) {
                wholePath.substring(i + 1)
            } else wholePath
        }
    }
}
