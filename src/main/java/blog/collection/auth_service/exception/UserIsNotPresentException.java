package blog.collection.auth_service.exception;

public class UserIsNotPresentException extends RuntimeException{
    public UserIsNotPresentException(String message) {
        super(message);
    }
}
