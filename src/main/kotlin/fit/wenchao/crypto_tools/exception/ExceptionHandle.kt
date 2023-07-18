package fit.wenchao.crypto_tools.exception

import cn.hutool.json.JSONObject
import fit.wenchao.crypto_tools.utils.ClassUtils
import mu.KotlinLogging
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


class BackendException : RuntimeException {
    var data: Any?
    var code: String
    var msg: String

    constructor(data: Any?, msg: String, code: String) {
        this.data = data
        this.code = code
        this.msg = msg
    }

    constructor(data: Any?, respCode: RespCode) {
        this.data = data
        this.code = respCode.getCode()
        msg = respCode.msg
    }

    constructor(cause: Throwable?, data: Any?, respCode: RespCode) : super(cause) {
        this.data = data
        this.code = respCode.getCode()
        msg = respCode.msg
    }
}


class ParameterCheckResult {
    var paramCheckMap: JSONObject = JSONObject()
    fun putResult(field: String?, message: String?) {
        paramCheckMap.put(field, message)
    }
}

/**
 * 全局异常处理类
 */
@ControllerAdvice
open class GlobalExceptionHandler {
    private val log = KotlinLogging.logger {}

    /**
     * 统一处理错误返回值
     */
    @ExceptionHandler(BackendException::class)
    @ResponseBody
    fun errorCodeException(req: HttpServletResponse?, ex: BackendException): JsonResult {
        val msg: String = ex.msg
        val jsonResult = JsonResult().apply {
            this.data = ex.data
            this.code = ex.code
            this.msg = ex.msg
        }
        log.error("[{}] {}", ex.code, msg)
        return jsonResult
    }

    @ExceptionHandler(
        BindException::class,
        MethodArgumentNotValidException::class
    )
    @ResponseBody
    fun paramValidateException(ex: Exception): JsonResult {
        var bindingResult: BindingResult? = null
        bindingResult = try {
            ClassUtils.getFieldValue(ex, "bindingResult", BindingResult::class.java)
        } catch (e: NoSuchFieldException) {
            log.error("获取参数校验信息失败")
            return JsonResult.of(null, RespCode.FRONT_END_PARAMS_ERROR)
        }
        val parameterCheckResult: ParameterCheckResult = bindingResultPackager(bindingResult)
        val jsonResult: JsonResult = JsonResult.of(parameterCheckResult, RespCode.FRONT_END_PARAMS_ERROR)
        log.error("Error:{}", jsonResult)
        return jsonResult
    }

    /**
     * 统一处理参数校验异常
     */
    @ExceptionHandler(ConstraintViolationException::class)
    @ResponseBody
    fun constraintViolationException(ex: ConstraintViolationException): JsonResult {
        val constraintViolations = ex.constraintViolations
        val parameterCheckResult = ParameterCheckResult()
        for (constraintViolation in constraintViolations) {
            parameterCheckResult.putResult(
                getLastPathNode(constraintViolation.propertyPath),
                constraintViolation.message
            )
        }
        return JsonResult.of(parameterCheckResult, RespCode.FRONT_END_PARAMS_ERROR)
    }

    private fun bindingResultPackager(bindingResult: BindingResult?): ParameterCheckResult {
        val parameterCheckResult = ParameterCheckResult()
        for (objectError in bindingResult!!.allErrors) {
            val fieldError = objectError as FieldError
            parameterCheckResult.putResult(fieldError.field, fieldError.defaultMessage)
        }
        return parameterCheckResult
    }

    // @Value("\${spring.servlet.multipart.max-file-size}")
    var uploadLimit: String? = null

    /**
     * 统一处理其他后端异常
     */
    @ExceptionHandler(Exception::class)
    @ResponseBody
    fun otherException(req: HttpServletResponse?, ex: Exception): JsonResult {
        log.error(
            "Server Exception-Name:{}，Server Exception-Msg:{}", ex.javaClass
                .typeName, ex.message
        )
        if (ex is HttpMessageNotReadableException) {
            return errorCodeException(req, BackendException("JSON parse error", RespCode.FRONT_END_PARAMS_ERROR))
        }
        if (ex is MissingServletRequestParameterException) {
            return errorCodeException(
                req,
                BackendException("Required request body is missing", RespCode.FRONT_END_PARAMS_ERROR)
            )
        }
        if (ex is MaxUploadSizeExceededException) {
            return errorCodeException(
                req,
                BackendException("Limitation: $uploadLimit", RespCode.UPLOAD_FILE_SIZE_EXCEED_UPPER_LIMIT)
            )
        }
        if (ex is MissingServletRequestPartException) {
            return errorCodeException(req, BackendException(ex.message ?: "", RespCode.FRONT_END_PARAMS_ERROR))
        }
        ex.printStackTrace()
        val jsonResult = JsonResult().apply {
            this.data = null
            this.code = RespCode.SERVER_ERROR.getCode()
            this.msg = "Server internal error occurred --> [ " + ex.javaClass
                .typeName + "-->" + ex.message + " ]"
        }
        return jsonResult
    }

    companion object {
        private fun getLastPathNode(path: Path): String {
            val wholePath = path.toString()
            val i = wholePath.lastIndexOf(".")
            return if (i != -1) {
                wholePath.substring(i + 1, wholePath.length)
            } else wholePath
        }
    }
}


