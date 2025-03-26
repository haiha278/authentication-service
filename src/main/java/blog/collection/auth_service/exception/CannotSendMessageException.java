package blog.collection.auth_service.exception;

public class CannotSendMessageException extends RuntimeException{
    public CannotSendMessageException(String message) {
        super(message);
    }
}
