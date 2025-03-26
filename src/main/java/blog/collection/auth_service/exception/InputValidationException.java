package blog.collection.auth_service.exception;

public class InputValidationException extends RuntimeException{
    public InputValidationException(String message) {
        super(message);
    }
}
