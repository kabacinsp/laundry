package pl.kabacinsp.laundry.user.repositories;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import pl.kabacinsp.laundry.user.dto.RoleType;
import pl.kabacinsp.laundry.user.dto.UserRole;

@Repository
public interface RoleRepository extends JpaRepository<UserRole, Long> {
    Optional<UserRole> findByName(RoleType name);
}
