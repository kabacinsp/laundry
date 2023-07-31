package pl.kabacinsp.laundry.user.utils;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

public class UserImpl extends User {

    private pl.kabacinsp.laundry.user.dto.User user;

    public UserImpl(pl.kabacinsp.laundry.user.dto.User user, Collection<? extends GrantedAuthority> authorities) {
        super(user.getEmail(), user.getPassword(), authorities);
        this.user = user;
    }

    public UserImpl(pl.kabacinsp.laundry.user.dto.User user, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
        super(user.getEmail(), user.getPassword(), enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
        this.user = user;
    }

    public pl.kabacinsp.laundry.user.dto.User getUser() {
        return user;
    }
}