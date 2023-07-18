package fit.wenchao.`crypto-tools`.exception

enum class RespCode(
    private val code: String, val msg: String,
) {
    SUCCESS("10000", "success"),

    FRONT_END_PARAMS_ERROR("10020", "front end params error"),
    INVALID_ENCODED_STRING("10020", "invalid encoded string"),

    SERVER_ERROR("10050", "server error"),

    UPLOAD_FILE_SIZE_EXCEED_UPPER_LIMIT("", "上传的文件大小大于上限"),

    Playground_Project_Template_Not_Exists("", "playground project template not exists"),
    Playground_Project_Location_Not_Set("", "playground project location not set"),
    Playground_Project_Delete_Failed("", "playground project delete failed"),
    Playground_Project_Not_Exists("", "playground project not exists"),
    Total_Size_Too_Large("", "total size too large"),
    Total_Count_Too_Large("", "total count too large"),
    System_Config_Not_Found("", "system config not found"),
    Playground_Project_Create_Failed("", "playground project create failed"),
    IDE_Home_Not_Set("", "IDEA home not set"),
    IDE_Start_Failed("", "IDEA start failed"),
    FILE_SYSTEM_ERROR("", "file system error"),
    ;


    fun getCode(): String {
        return name
    }


}

