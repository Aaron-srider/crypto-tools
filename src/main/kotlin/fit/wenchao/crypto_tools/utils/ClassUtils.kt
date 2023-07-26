package fit.wenchao.crypto_tools.utils

import mu.KotlinLogging
import org.springframework.web.method.HandlerMethod
import java.lang.reflect.Field
import java.lang.reflect.Method


object ClassUtils {
    private val log = KotlinLogging.logger {}
    @Throws(NoSuchFieldException::class)
    fun <T> getFieldValue(obj: Any, fieldName: String?, fieldType: Class<T>): T? {
        var declaredField: Field? = null
        val targetClass: Class<*> = obj.javaClass
        declaredField = try {
            targetClass.getDeclaredField(fieldName)
        } catch (e: NoSuchFieldException) {
            throw e
        }
        val fieldActualClass = declaredField!!.type
        if (!fieldType.isAssignableFrom(fieldActualClass)) {
            log.error("指定的字段类型:{}与实际属性的类型：{}不匹配", fieldType, fieldActualClass)
            throw RuntimeException("指定的字段类型与实际属性的类型不匹配")
        }
        declaredField.isAccessible = true
        var targetFieldValue: T? = null
        targetFieldValue = try {
            declaredField[obj] as T
        } catch (e: IllegalAccessException) {
            throw RuntimeException(e)
        }
        return targetFieldValue
    }

    private fun getMethodSig(method: Method): String {
        return method.name + "-" + getMethodTypeString(method)
    }

    fun getMethodSig(method: HandlerMethod): String {
        return getMethodSig(method.method)
    }

    private fun getMethodTypeString(declaredMethod: Method): String {
        if (declaredMethod.parameterCount == 0) {
            return ""
        }
        val sb = StringBuilder()
        val parameterTypes = declaredMethod.parameterTypes
        for (paramType in parameterTypes) {
            sb.append(paramType.typeName + "-")
        }
        return sb.substring(0, sb.length - 1)
    }

    fun <T : Annotation?> getFieldAnnotation(annotation: Class<T>?, target: Class<*>): T? {
        val declaredFields = target.declaredFields
        for (declaredField in declaredFields) {
            declaredField.isAccessible = true
            val annotation1 = declaredField.getAnnotation(annotation)
            if (annotation1 != null) {
                return annotation1
            }
        }
        return null
    }

    fun <T : Annotation?> getFieldAnnotatedBy(annotation: Class<T>?, target: Class<*>): Field? {
        val declaredFields = target.declaredFields
        for (declaredField in declaredFields) {
            declaredField.isAccessible = true
            val annotation1 = declaredField.getAnnotation(annotation)
            if (annotation1 != null) {
                return declaredField
            }
        }
        return null
    }
}

