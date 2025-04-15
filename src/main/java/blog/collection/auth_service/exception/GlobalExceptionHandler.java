//package blog.collection.auth_service.exception;
//
//import blog.collection.auth_service.common.CommonString;
//import blog.collection.auth_service.dto.responseDTO.commonResponse.BaseResponse;
//import jakarta.servlet.http.HttpServletRequest;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.authentication.BadCredentialsException;
//import org.springframework.security.authentication.DisabledException;
//import org.springframework.security.authentication.InternalAuthenticationServiceException;
//import org.springframework.security.authentication.LockedException;
//import org.springframework.web.bind.annotation.ControllerAdvice;
//import org.springframework.web.bind.annotation.ExceptionHandler;
//import blog.collection.auth_service.dto.responseDTO.commonResponse.ErrorResponse;
//
//import java.time.LocalDateTime;
//
//@ControllerAdvice
//public class GlobalExceptionHandler {
//    @ExceptionHandler(UsernameNotFoundException.class)
//    public ResponseEntity<Object> handlerResourceNotFoundException(UsernameNotFoundException e, HttpServletRequest httpServletRequest) {
//        return new ResponseEntity<>(new BaseResponse<>(new ErrorResponse(LocalDateTime.now(), HttpStatus.NOT_FOUND.value(), HttpStatus.NOT_FOUND.getReasonPhrase(), e.getMessage(), httpServletRequest.getRequestURI())), HttpStatus.NOT_FOUND);
//    }
//
//    @ExceptionHandler(AuthenticationFailException.class)
//    public ResponseEntity<Object> handlerAuthenticationFailException(AuthenticationFailException e, HttpServletRequest httpServletRequest) {
//        return new ResponseEntity<>(new BaseResponse<>(new ErrorResponse(LocalDateTime.now(), HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase(), e.getMessage(), httpServletRequest.getRequestURI())), HttpStatus.FORBIDDEN);
//    }
//
//    @ExceptionHandler(Exception.class)
//    public ResponseEntity<Object> handlerException(Exception e, HttpServletRequest httpServletRequest) {
//        return new ResponseEntity<>(new BaseResponse<>(new ErrorResponse(LocalDateTime.now(), HttpStatus.INTERNAL_SERVER_ERROR.value(), HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase(), CommonString.INTERNAL_SERVER_ERROR, httpServletRequest.getRequestURI())), HttpStatus.INTERNAL_SERVER_ERROR);
//    }
//
//    @ExceptionHandler(CreatedLocalUserFailException.class)
//    public ResponseEntity<Object> handlerCreatedLocalUserFailException(CreatedLocalUserFailException e, HttpServletRequest httpServletRequest) {
//        return new ResponseEntity<>(new BaseResponse<>(new ErrorResponse(LocalDateTime.now(), HttpStatus.BAD_REQUEST.value(), HttpStatus.BAD_REQUEST.getReasonPhrase(), e.getMessage(), httpServletRequest.getRequestURI())), HttpStatus.BAD_REQUEST);
//    }
//
//    @ExceptionHandler(CannotSendMessageException.class)
//    public ResponseEntity<Object> handlerCannotSendMessageException(CannotSendMessageException e, HttpServletRequest httpServletRequest) {
//        return new ResponseEntity<>(new BaseResponse<>(new ErrorResponse(LocalDateTime.now(), HttpStatus.SERVICE_UNAVAILABLE.value(), HttpStatus.SERVICE_UNAVAILABLE.getReasonPhrase(), e.getMessage(), httpServletRequest.getRequestURI())), HttpStatus.SERVICE_UNAVAILABLE);
//    }
//
//    @ExceptionHandler(EmailVerificationException.class)
//    public ResponseEntity<Object> handlerOtpVerificationException(EmailVerificationException e, HttpServletRequest httpServletRequest) {
//        return new ResponseEntity<>(new BaseResponse<>(new ErrorResponse(LocalDateTime.now(), HttpStatus.NOT_ACCEPTABLE.value(), HttpStatus.NOT_ACCEPTABLE.getReasonPhrase(), e.getMessage(), httpServletRequest.getRequestURI())), HttpStatus.NOT_ACCEPTABLE);
//    }
//
//    @ExceptionHandler(InputValidationException.class)
//    public ResponseEntity<Object> handlerInputValidationException(InputValidationException e, HttpServletRequest httpServletRequest) {
//        return new ResponseEntity<>(new BaseResponse<>(new ErrorResponse(LocalDateTime.now(), HttpStatus.NOT_ACCEPTABLE.value(), HttpStatus.NOT_ACCEPTABLE.getReasonPhrase(), e.getMessage(), httpServletRequest.getRequestURI())), HttpStatus.NOT_ACCEPTABLE);
//    }
//
//    @ExceptionHandler(UserIsNotPresentException.class)
//    public ResponseEntity<Object> handlerUserIsNotPresentException(UserIsNotPresentException e, HttpServletRequest httpServletRequest) {
//        return new ResponseEntity<>(new BaseResponse<>(new ErrorResponse(LocalDateTime.now(), HttpStatus.NOT_FOUND.value(), HttpStatus.NOT_FOUND.getReasonPhrase(), e.getMessage(), httpServletRequest.getRequestURI())), HttpStatus.NOT_FOUND);
//    }
//
//    @ExceptionHandler(BadCredentialsException.class)
//    public ResponseEntity<Object> handlerBadCredentialsException(BadCredentialsException e, HttpServletRequest httpServletRequest) {
//        return new ResponseEntity<>(new BaseResponse<>(new ErrorResponse(LocalDateTime.now(), HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase(), "Invalid username or password", httpServletRequest.getRequestURI())), HttpStatus.UNAUTHORIZED);
//    }
//
//    @ExceptionHandler(DisabledException.class)
//    public ResponseEntity<Object> handlerDisabledException(DisabledException e, HttpServletRequest httpServletRequest) {
//        return new ResponseEntity<>(new BaseResponse<>(new ErrorResponse(LocalDateTime.now(), HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase(), "Account is disabled", httpServletRequest.getRequestURI())), HttpStatus.NOT_FOUND);
//    }
//
//    @ExceptionHandler(InternalAuthenticationServiceException.class)
//    public ResponseEntity<Object> handlerInternalAuthenticationServiceException(InternalAuthenticationServiceException e, HttpServletRequest request) {
//        return new ResponseEntity<>(new BaseResponse<>(new ErrorResponse(LocalDateTime.now(), HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase(), "Invalid username or password", request.getRequestURI())), HttpStatus.UNAUTHORIZED);
//    }
//
//    @ExceptionHandler(LockedException.class)
//    public ResponseEntity<Object> handlerLockedException(LockedException e, HttpServletRequest httpServletRequest) {
//        return new ResponseEntity<>(new BaseResponse<>(new ErrorResponse(LocalDateTime.now(), HttpStatus.LOCKED.value(), HttpStatus.LOCKED.getReasonPhrase(), "Account is locked", httpServletRequest.getRequestURI())), HttpStatus.NOT_FOUND);
//    }
//}
