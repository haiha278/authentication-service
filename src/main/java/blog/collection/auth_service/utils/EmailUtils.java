package blog.collection.auth_service.utils;

import blog.collection.auth_service.common.CommonString;
import blog.collection.auth_service.dto.requestDTO.AddLocalAuthenticationUserRequestDTO;
import blog.collection.auth_service.dto.requestDTO.ResetPasswordRequestDTO;
import blog.collection.auth_service.dto.requestDTO.UserVerificationData;
import blog.collection.auth_service.dto.tranferMessage.CreateUserTransferMessage;
import blog.collection.auth_service.exception.EmailVerificationException;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
public class EmailUtils {

    private final JavaMailSender javaMailSender;

    private final RedisTemplate<String, Object> redisTemplate;

    @Autowired
    public EmailUtils(JavaMailSender javaMailSender, RedisTemplate<String, Object> redisTemplate) {
        this.javaMailSender = javaMailSender;
        this.redisTemplate = redisTemplate;
    }

    //24 hour
    private static final long EXPIRATION_TIME = 24;

    private static final String EMAIL_TEMPLATE =
            "<div marginheight=\"0\" marginwidth=\"0\" style=\"margin:0px;background-color:#f2f3f8\">" +
                    "<table cellspacing=\"0\" border=\"0\" cellpadding=\"0\" width=\"100%\" bgcolor=\"#f2f3f8\" style=\"font-family:'Open Sans',sans-serif\">" +
                    "<tbody><tr><td><table style=\"background-color:#f2f3f8;max-width:670px;margin:0 auto\" width=\"100%\" border=\"0\" align=\"center\" cellpadding=\"0\" cellspacing=\"0\">" +
                    "<tbody><tr><td style=\"height:80px\"> </td></tr><tr><td style=\"text-align:center\"><a title=\"logo\"><img></a></td></tr><tr><td style=\"height:20px\"> </td></tr><tr><td>" +
                    "<table width=\"95%\" border=\"0\" align=\"center\" cellpadding=\"0\" cellspacing=\"0\" style=\"max-width:670px;background:#fff;border-radius:3px;text-align:center\"><tbody><tr><td style=\"height:40px\"> </td></tr><tr><td style=\"padding:0 35px\">" +
                    "<h1 style=\"color:#1e1e2d;font-weight:500;margin:0;font-size:32px;font-family:'Rubik',sans-serif\">{ACTION_TITLE}</h1>" +
                    "<span style=\"display:inline-block;vertical-align:middle;margin:29px 0 26px;border-bottom:1px solid #cecece;width:100px\"><p style=\"color:#455056;font-size:15px;line-height:24px;margin:0\">Click the link below to {ACTION_TEXT}</p></span><br>" +
                    "<a href=\"{{ACTION_LINK}}\" style=\"background:#10b981;text-decoration:none!important;font-weight:500;margin-top:10px;color:#fff;text-transform:uppercase;font-size:14px;padding:10px 24px;display:inline-block;border-radius:50px\">{ACTION_BUTTON}</a>" +
                    "<p style=\"color:#455056;font-size:15px;line-height:24px;margin-top:10px\">This link will expire 1 day after this email was sent.</p>" +
                    "<p>{ACTION_FOOTER}</p></td></tr><tr><td style=\"height:40px\"> </td></tr></tbody></table>" +
                    "</td></tr><tr><td style=\"height:20px\"> </td></tr><tr><td style=\"text-align:center\">" +
                    "<p style=\"font-size:14px;color:rgba(69,80,86,0.7411764705882353);line-height:18px;margin:0 0 0\">© <strong><a>noreply@blog-collection.id.vn</a></strong></p>" +
                    "</td></tr><tr><td style=\"height:80px\"> </td></tr></tbody></table></td></tr></tbody></table></div>";

    public void sendToVerifyEmail(CreateUserTransferMessage userData) throws MessagingException {
        String token = UUID.randomUUID().toString();

        String emailContent = EMAIL_TEMPLATE
                .replace("{ACTION_TITLE}", "Verify your Account")
                .replace("{ACTION_TEXT}", "verify this account belongs to you")
                .replace("{{ACTION_LINK}}", "http://localhost:8080/auth/verify-email?token=" + token)
                .replace("{ACTION_BUTTON}", "Verify Now!")
                .replace("{ACTION_FOOTER}", "Blog Collection requires verification whenever an email address is selected to register for an account. You cannot access your account until you verify it.");

        sendEmail(userData.getEmail(), "Email Verification", emailContent, userData, token);
    }

    public void sentToResetPassword(ResetPasswordRequestDTO resetPasswordRequestDTO) throws MessagingException {
        String token = UUID.randomUUID().toString();

        String emailContent = EMAIL_TEMPLATE
                .replace("{ACTION_TITLE}", "Reset your Password")
                .replace("{ACTION_TEXT}", "reset your password")
                .replace("{{ACTION_LINK}}", "http://localhost:8080/auth/reset-password?token=" + token)
                .replace("{ACTION_BUTTON}", "Reset Now!")
                .replace("{ACTION_FOOTER}", "Please use the link above to proceed.");

        sendEmail(resetPasswordRequestDTO.getEmail(), "Reset Password", emailContent, resetPasswordRequestDTO, token);
    }

    private void sendEmail(String to, String subject, String emailContent, Object data, String token) throws MessagingException {
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED, StandardCharsets.UTF_8.name());
        mimeMessageHelper.setTo(to);
        mimeMessageHelper.setSubject(subject);
        mimeMessageHelper.setText(emailContent, true);

        try {
            if (data != null) {
                redisTemplate.opsForValue().set(CommonString.VERIFY_EMAIL_KEY_PREFIX + token, data, EXPIRATION_TIME, TimeUnit.HOURS);
            }
            javaMailSender.send(mimeMessage);
        } catch (Exception e) {
            throw new EmailVerificationException("Failed to send email");
        }
    }

}

