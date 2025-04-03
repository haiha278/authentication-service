package blog.collection.auth_service.common;

public class CommonString {
    public static final String USERNAME_NOT_FOUND = "Username Not Found";

    public static final String CREATE_NEW_USER_SUCCESSFULLY = "Create new user successfully";

    public static final String INTERNAL_SERVER_ERROR = "Internal server error";

    public static final String LOGIN_SUCCESSFULLY = "Login successfully";

    public static final String CAN_NOT_CREATE_NEW_USER = "Can not create new user";

    public static final String EMAIL_IS_EXISTED = "Email is existed";

    public static final String USERNAME_IS_EXISTED = "Username is existed";

    public static final String CAN_NOT_SEND_EMAIL = "Fail to send email";

    public static final String SEND_MESSAGE_TO_EMAIL_SUCCESSFULLY = "Send message to email successfully";

    public static final String EXPIRED_EMAIL_VERIFY_LINK = "Link is expired";

    public static final String EMAIL_REGEX = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";

    public static final String WRONG_EMAIL_FORMAT = "Email is wrong format";

    public static final String WRONG_PHONE_FORMAT = "Phone is wrong format";

    public static final String PHONE_REGEX = "^0\\d{9}$";

    //Password se co it nhat 8 ki tu, ca chu va so bao gom 1 chu in hoa va 1 ki tu dac biet
    public static final String PASSWORD_FORMAT = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[\\W_]).{8,}$";

    public static final String WRONG_PASSWORD_FORMAT = "Password is not matched with requirement";

    public static final String CAN_NOT_LOGIN_BY_GOOGLE = "Can not login by Google";

    public static final String CAN_NOT_FIND_ACCOUNT = "Account is not existed";

    public static final String CONFIRM_PASSWORD_MUST_SAME = "Confirm Password must same with password";

    public static final String RESET_PASSWORD_SUCCESSFULLY = "Reset password successfully";

    public static final String CURRENT_PASSWORD_WRONG = "Current password is wrong";

    public static final String DATA_CAN_NOT_BE_NULL = "Can not be empty";

    public static final String CHANGE_PASSWORD_SUCCESSFULLY = "Change password successfully";

    public static final String VERIFY_EMAIL_KEY_PREFIX = "email-verification:token: ";
}
