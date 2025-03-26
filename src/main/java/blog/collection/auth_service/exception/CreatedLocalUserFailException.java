package blog.collection.auth_service.exception;

public class CreatedLocalUserFailException extends RuntimeException{
    public CreatedLocalUserFailException(String message) {
        super(message);
    }
}
