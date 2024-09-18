class ApiResponse {
    constructor (
        statusCode,
        message = "operation successfull",
        data = ""
    ){
        this.statusCode = statusCode < 400
        this.message = message
        this.data = data
        success = true
    }
}