package pl.kabacinsp.laundry.user.dto;

import jakarta.persistence.*;
import java.util.Set;

@Entity
@Table(name = "role")
public class UserRole {

    @Id
    //Slight increase in performance over GenerationType.IDENTITY
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "role_id", updatable = false, nullable = false)
    private long role_id;

    @Column(name = "role", nullable = false)
    private RoleType name;

    /**
     * Many to Many Example - see Role.
     * <p>
     * One User many have many Roles.
     * Each Role may be assigned to many Users.
     */
    @ManyToMany(mappedBy = "roles", fetch = FetchType.EAGER)
    private Set<User> users;

    public long getRole_id() {
        return role_id;
    }

    public void setRole_id(long role_id) {
        this.role_id = role_id;
    }

    public RoleType getName() {
        return name;
    }

    public void setName(String name) {
        this.name = RoleType.valueOf(name);
    }

    public Set<User> getUsers() {
        return users;
    }

    public void setUsers(Set<User> users) {
        this.users = users;
    }
}
