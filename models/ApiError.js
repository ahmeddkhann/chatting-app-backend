class ApiError extends Error {
    constructor (
        statusCode,
        message = "something went wrong",
        errors = [],
        stack = ""
    ){
        super (message)
        this.statusCode = statusCode
        this.errors = errors
        this.message = message
        data = null
        success = false

        if (stack) {
            this.stack = stack
        }
    }
}

export {ApiError}