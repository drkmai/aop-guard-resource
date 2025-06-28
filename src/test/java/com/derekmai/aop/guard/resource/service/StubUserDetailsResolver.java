package com.derekmai.aop.guard.resource.service;

import com.derekmai.aop.guard.resource.user.UserDetailsResolver;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Collections;

@Component
public class StubUserDetailsResolver implements UserDetailsResolver {
    @Override
    public UserDetails resolve(Object param) {
        return new User(
                "username",
                "password",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_TEAM_ADMIN_0000-0000"))
        );
    }
}
