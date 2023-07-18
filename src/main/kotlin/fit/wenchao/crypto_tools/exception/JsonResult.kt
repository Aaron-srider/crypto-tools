package fit.wenchao.crypto_tools.exception


class JsonResult {
    var data: Any? = null
    var code: String? = null
    var msg: String? = null

    companion object {
        fun of(data: Any?, respCode: RespCode): JsonResult {
            val jsonResult = JsonResult()
            jsonResult.data = data
            jsonResult.code = respCode.getCode()
            jsonResult.msg = respCode.msg
            return jsonResult
        }

        fun of(data: Any?, code: String?, msg: String?): JsonResult {
            val jsonResult = JsonResult()
            jsonResult.data = data
            jsonResult.code = code
            jsonResult.msg = msg
            return jsonResult
        }

        fun ok(): JsonResult {
            return JsonResult().apply {
                this.data = null
                this.code = RespCode.SUCCESS.getCode()
                this.msg = RespCode.SUCCESS.msg
            }
        }

        fun ok(data: Any?): JsonResult {
            return JsonResult().apply {
                this.data = data
                this.code = RespCode.SUCCESS.getCode()
                this.msg = RespCode.SUCCESS.msg
            }
        }
    }
}
