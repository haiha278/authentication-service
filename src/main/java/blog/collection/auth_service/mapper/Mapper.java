package blog.collection.auth_service.mapper;

import org.modelmapper.ModelMapper;

public class Mapper {
    private static final ModelMapper mapper = new ModelMapper();

    public static <T, U> T mapEntityToDto(U entity, Class<T> dtoClass) {
        return mapper.map(entity, dtoClass);
    }

    public static <T, U> U mapDtoToEntity(T dto, Class<U> entityClass) {
        return mapper.map(dto, entityClass);
    }
}
