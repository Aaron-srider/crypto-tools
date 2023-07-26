package fit.wenchao.crypto_tools.exception

class JsonResult {
    var code = ErrorCode.UNKNOWN.name
    var msg: String? = null
    var data: Any? = null

    constructor()
    constructor(code: String, msg: String?, data: Any?) {
        this.code = code
        this.msg = msg
        this.data = data
    }

    constructor(errorCode: ErrorCode, data: Any?) {
        this.code = errorCode.name
        msg = errorCode.name
        this.data = data
    }

    override fun toString(): String {
        return "JsonResult{" +
                "code='" + code + '\'' +
                ", msg='" + msg + '\'' +
                ", data=" + data +
                '}'
    }

    companion object {
        fun ok(): JsonResult {
            return JsonResult(ErrorCode.SUCCESS.name, ErrorCode.SUCCESS.name, null)
        }

        fun ok(data: Any?): JsonResult {
            return JsonResult(ErrorCode.SUCCESS.name, ErrorCode.SUCCESS.name, data)
        }
    }
}
