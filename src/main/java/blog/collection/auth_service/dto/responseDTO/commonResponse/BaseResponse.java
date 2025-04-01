package blog.collection.auth_service.dto.responseDTO.commonResponse;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@RequiredArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class BaseResponse<T> {
    private int responseCode;
    private String responseMessage;
    private T responseData;

    public BaseResponse(T responseData) {
        this.responseData = responseData;
    }

    public BaseResponse(int responseCode, T responseData) {
        this.responseCode = responseCode;
        this.responseData = responseData;
    }
}
