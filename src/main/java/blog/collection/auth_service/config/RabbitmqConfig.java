package blog.collection.auth_service.config;

import org.springframework.amqp.core.Queue;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitmqConfig {
    public static final String USER_CREATE_REQUEST_QUEUE = "user-create-request";
    public static final String USER_CREATE_RESPONSE_QUEUE = "user-create-response";

    @Bean
    public Queue userCreateRequestQueue() {
        return new Queue(USER_CREATE_REQUEST_QUEUE, true);
    }

    @Bean
    public Queue userCreateResponseQueue() {
        return new Queue(USER_CREATE_RESPONSE_QUEUE, true);
    }
}
