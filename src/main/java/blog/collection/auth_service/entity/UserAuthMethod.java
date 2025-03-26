package blog.collection.auth_service.entity;

import blog.collection.auth_service.common.AuthProvider;
import jakarta.persistence.*;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "user_auth_method", uniqueConstraints = {@UniqueConstraint(columnNames = {"user_id", "auth_provider"})})
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserAuthMethod {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, name = "auth_provider")
    private AuthProvider authProvider;

    @Column(unique = true, name = "provider_user_id")
    private String providerUserId;

    @Column(name = "password")
    private String passwordHash;

    @Column(name = "username", unique = true)
    private String username;

    @Column(name = "created_time")
    private String createdAt = LocalDateTime.now().toString();

    @Column(name = "updated_time")
    private String updateAt = LocalDateTime.now().toString();

    @ManyToOne
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;
}
