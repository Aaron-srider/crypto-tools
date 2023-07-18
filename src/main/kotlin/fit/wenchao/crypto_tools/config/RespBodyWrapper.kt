package fit.wenchao.crypto_tools.config
import com.alibaba.fastjson.JSONObject
import fit.wenchao.crypto_tools.exception.JsonResult
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.core.MethodParameter
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.HttpMessageConverter
import org.springframework.http.converter.StringHttpMessageConverter
import org.springframework.http.server.ServerHttpRequest
import org.springframework.http.server.ServerHttpResponse
import org.springframework.stereotype.Component
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice

interface RespBodyWrapper {

    fun wrap(body: Any?): Any

    fun need2Wrap(returnType: MethodParameter): Boolean
}

@Component
open class JsonResultRespBodyWrapper : RespBodyWrapper {
    override fun wrap(body: Any?): Any {
        return JsonResult.ok(body)
    }

    override fun need2Wrap(returnType: MethodParameter): Boolean {
        return returnType.parameterType != JsonResult::class.java
    }
}

@ControllerAdvice
open class ResponseWrapperAdvice : ResponseBodyAdvice<Any?> {

    @Autowired
    @Qualifier("jsonResultRespBodyWrapper")
    lateinit var respWrapper: RespBodyWrapper

    override fun supports(
        returnType: org.springframework.core.MethodParameter,
        converterType: Class<out HttpMessageConverter<*>>,
    ): Boolean {
        return returnType.parameterType != ResponseEntity::class.java // Return true to enable the advice for all controller methods
    }

    override fun beforeBodyWrite(
        body: Any?,
        returnType: MethodParameter,
        selectedContentType: MediaType,
        selectedConverterType: Class<out HttpMessageConverter<*>>,
        request: ServerHttpRequest,
        response: ServerHttpResponse,
    ): Any? {
//        return "hello"
        // we handle string return type rather then let springboot taking over, because we want to wrap the string with json result
        // in which case the selected converter for string is StringHttpMessageConverter, which can not do the job MappingJackson2HttpMessageConverter can do
        if(selectedConverterType == StringHttpMessageConverter::class.java) {
            // spring mvc will set the content type to text/plain;charset=UTF-8 for string, we need to change it to application/json;charset=UTF-8
            response.headers.set("Content-Type", "application/json;charset=UTF-8")
            return JSONObject.toJSONString(respWrapper.wrap(body))
        }
        if (respWrapper.need2Wrap(returnType)) {
            return respWrapper.wrap(body)
        }
        return body
    }
}