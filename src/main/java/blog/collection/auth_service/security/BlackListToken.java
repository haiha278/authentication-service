package blog.collection.auth_service.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class BlackListToken {
    private static final String BLACK_LIST_KEY_PREFIX = "blacklist:token: ";

    private final RedisTemplate<String, String> redisTemplate;

    public void addTokenIntoBlackList(String token, long timeInMilliSeconds){
        redisTemplate.opsForValue().set(BLACK_LIST_KEY_PREFIX + token, "blackedlist", timeInMilliSeconds, TimeUnit.MILLISECONDS);
    }

    public boolean isTokenBlackList(String token){
        return Boolean.TRUE.equals(redisTemplate.hasKey(token));
    }
}
