package com.derekmai.aop.guard.resource;

import com.derekmai.aop.guard.resource.model.SubTeamModel;
import com.derekmai.aop.guard.resource.model.TeamModel;
import com.derekmai.aop.guard.resource.model.TestModel;
import com.derekmai.aop.guard.resource.service.StubUserDetailsResolver;
import com.derekmai.aop.guard.resource.service.TestService;
import com.derekmai.aop.guard.resource.user.DefaultUserDetailsResolver;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.context.ApplicationContext;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
public class GuardResourceTest {

    @Mock
    StubUserDetailsResolver stubUserDetailsResolver;

    private final AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();

    private final String pointcutExpression = "@annotation(com.derekmai.aop.guard.resource.GuardResource)";

    private static TestModel buildTestModelWith(String id, String teamId) {
        return new TestModel(id, new TeamModel(teamId));
    }

    private static User buildUserDetailsWithAuthorities(List<String> authorities) {
        Collection<SimpleGrantedAuthority> authorityCollection = authorities.stream().map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        return new User(
                "username",
                "password",
                authorityCollection
        );
    }

    @Before
    public void setup() {
        pointcut.setExpression(pointcutExpression);
    }

    @Test
    public void when_correctAuthorityIsGranted_then_AccessResource() throws Throwable {
        ApplicationContext context = mock(ApplicationContext.class);
        GuardResourceAspect aspect = new GuardResourceAspect(context);
        Method testMethod = TestService.class.getMethod("securedMethod");
        assertTrue(pointcut.matches(testMethod, TestService.class));

        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(testMethod);
        when(invocation.proceed()).thenReturn(buildTestModelWith("abcd-1234", "1234-5678"));

        UserDetails userDetails = buildUserDetailsWithAuthorities(Collections.singletonList("ROLE_TEAM_USER_1234-5678"));
        DefaultUserDetailsResolver resolver = mock(DefaultUserDetailsResolver.class);
        when(resolver.resolve(any())).thenReturn(userDetails);
        when(context.getBean(DefaultUserDetailsResolver.class)).thenReturn(resolver);

        Object result = aspect.guardResource(invocation);
        assertNotNull(result);
    }

    @Test(expected = AccessDeniedException.class)
    public void when_incorrectAuthorityIsGranted_then_DenyAccess() throws Throwable {
        ApplicationContext context = mock(ApplicationContext.class);
        GuardResourceAspect aspect = new GuardResourceAspect(context);

        Method testMethod = TestService.class.getMethod("securedMethod");
        assertTrue(pointcut.matches(testMethod, TestService.class));

        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(testMethod);
        when(invocation.proceed()).thenReturn(buildTestModelWith("abcd-1234", "1234-5678"));

        UserDetails userDetails = buildUserDetailsWithAuthorities(Collections.singletonList("ROLE_TEAM_USER_5678-1234"));
        DefaultUserDetailsResolver resolver = mock(DefaultUserDetailsResolver.class);
        when(resolver.resolve(any())).thenReturn(userDetails);
        when(context.getBean(DefaultUserDetailsResolver.class)).thenReturn(resolver);

        aspect.guardResource(invocation);
    }

    @Test(expected = AccessDeniedException.class)
    public void when_userDoesNotHaveAuthorities_then_DenyAccess() throws Throwable {
        ApplicationContext context = mock(ApplicationContext.class);
        GuardResourceAspect aspect = new GuardResourceAspect(context);

        Method testMethod = TestService.class.getMethod("securedMethod");
        assertTrue(pointcut.matches(testMethod, TestService.class));

        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(testMethod);
        when(invocation.proceed()).thenReturn(buildTestModelWith("abcd-1234", "1234-5678"));

        UserDetails userDetails = buildUserDetailsWithAuthorities(Collections.emptyList());
        DefaultUserDetailsResolver resolver = mock(DefaultUserDetailsResolver.class);
        when(resolver.resolve(any())).thenReturn(userDetails);
        when(context.getBean(DefaultUserDetailsResolver.class)).thenReturn(resolver);
        aspect.guardResource(invocation);
    }

    @Test(expected = AccessDeniedException.class)
    public void when_modelDoesNotHaveProperAccessors_then_DenyAccess() throws Throwable {
        ApplicationContext context = mock(ApplicationContext.class);
        GuardResourceAspect aspect = new GuardResourceAspect(context);

        Method testMethod = TestService.class.getMethod("securedMethod2");
        assertTrue(pointcut.matches(testMethod, TestService.class));

        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(testMethod);
        when(invocation.proceed()).thenReturn(buildTestModelWith("abcd-1234", "1234-5678"));

        UserDetails userDetails = buildUserDetailsWithAuthorities(Collections
                .singletonList("ROLE_SUBTEAM_USER_5678-1234"));
        DefaultUserDetailsResolver resolver = mock(DefaultUserDetailsResolver.class);
        when(resolver.resolve(any())).thenReturn(userDetails);
        when(context.getBean(DefaultUserDetailsResolver.class)).thenReturn(resolver);
        aspect.guardResource(invocation);
    }

    @Test
    public void when_correctAuthorityIsGrantedForOneScope_then_AccessResource() throws Throwable {
        ApplicationContext context = mock(ApplicationContext.class);
        GuardResourceAspect aspect = new GuardResourceAspect(context);

        Method testMethod = TestService.class.getMethod("securedMethod2");
        assertTrue(pointcut.matches(testMethod, TestService.class));

        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(testMethod);
        when(invocation.proceed()).thenReturn(new SubTeamModel("1234-5678", new TeamModel("abcdef")));

        UserDetails userDetails = buildUserDetailsWithAuthorities(Collections.singletonList("ROLE_SUBTEAM_USER_1234-5678"));
        DefaultUserDetailsResolver resolver = mock(DefaultUserDetailsResolver.class);
        when(resolver.resolve(any())).thenReturn(userDetails);
        when(context.getBean(DefaultUserDetailsResolver.class)).thenReturn(resolver);

        Object result = aspect.guardResource(invocation);
        assertNotNull(result);
    }

    @Test
    public void when_correctAuthorityIsGrantedForOneScope_then_AccessResource_2() throws Throwable {
        ApplicationContext context = mock(ApplicationContext.class);
        GuardResourceAspect aspect = new GuardResourceAspect(context);

        Method testMethod = TestService.class.getMethod("securedMethod2");
        assertTrue(pointcut.matches(testMethod, TestService.class));

        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(testMethod);
        when(invocation.proceed()).thenReturn(new SubTeamModel("1234-5678", new TeamModel("abcdef")));

        UserDetails userDetails = buildUserDetailsWithAuthorities(Collections.singletonList("ROLE_TEAM_ADMIN_abcdef"));
        DefaultUserDetailsResolver resolver = mock(DefaultUserDetailsResolver.class);
        when(resolver.resolve(any())).thenReturn(userDetails);
        when(context.getBean(DefaultUserDetailsResolver.class)).thenReturn(resolver);

        Object result = aspect.guardResource(invocation);
        assertNotNull(result);
    }

    @Test
    public void when_correctAuthorityIsGrantedForAllUsersInvolved_then_AccessResource() throws Throwable {
        ApplicationContext context = mock(ApplicationContext.class);
        GuardResourceAspect aspect = new GuardResourceAspect(context);

        Method testMethod = TestService.class.getMethod("securedMethod3", String.class);
        assertTrue(pointcut.matches(testMethod, TestService.class));

        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(testMethod);
        when(invocation.getArguments()).thenReturn(new Object[]{"myUserId"});
        when(invocation.proceed()).thenReturn(new SubTeamModel("1234-5678", new TeamModel("abcdef")));

        UserDetails defaultUserDetails = buildUserDetailsWithAuthorities(Collections
                .singletonList("ROLE_SUBTEAM_USER_1234-5678"));
        DefaultUserDetailsResolver resolver = mock(DefaultUserDetailsResolver.class);
        when(resolver.resolve(any())).thenReturn(defaultUserDetails);
        when(context.getBean(DefaultUserDetailsResolver.class)).thenReturn(resolver);

        UserDetails fromParamUserDetails = buildUserDetailsWithAuthorities(Collections
                .singletonList("ROLE_TEAM_ADMIN_abcdef"));
        StubUserDetailsResolver stubResolver = mock(StubUserDetailsResolver.class);
        when(stubResolver.resolve(any())).thenReturn(fromParamUserDetails);
        when(context.getBean(StubUserDetailsResolver.class)).thenReturn(stubResolver);

        Object result = aspect.guardResource(invocation);
        assertNotNull(result);
    }

    @Test(expected = AccessDeniedException.class)
    public void when_onlyCustomResolverHasAccess_then_DenyAccess() throws Throwable {
        ApplicationContext context = mock(ApplicationContext.class);
        GuardResourceAspect aspect = new GuardResourceAspect(context);

        Method testMethod = TestService.class.getMethod("securedMethod3", String.class);
        assertTrue(pointcut.matches(testMethod, TestService.class));

        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(testMethod);
        when(invocation.getArguments()).thenReturn(new Object[]{"myUserId"});
        when(invocation.proceed()).thenReturn(new SubTeamModel("1234-5678", new TeamModel("abcdef")));

        UserDetails defaultUserDetails = buildUserDetailsWithAuthorities(Collections
                .singletonList("ROLE_SUBTEAM_USER_5678"));
        DefaultUserDetailsResolver resolver = mock(DefaultUserDetailsResolver.class);
        when(resolver.resolve(any())).thenReturn(defaultUserDetails);
        when(context.getBean(DefaultUserDetailsResolver.class)).thenReturn(resolver);

        UserDetails fromParamUserDetails = buildUserDetailsWithAuthorities(Collections
                .singletonList("ROLE_TEAM_ADMIN_abcdef"));
        StubUserDetailsResolver stubResolver = mock(StubUserDetailsResolver.class);
        when(stubResolver.resolve(any())).thenReturn(fromParamUserDetails);
        when(context.getBean(StubUserDetailsResolver.class)).thenReturn(stubResolver);

        Object result = aspect.guardResource(invocation);
        assertNotNull(result);
    }

    @Test(expected = AccessDeniedException.class)
    public void when_onlyDefaultResolverHasAccess_then_DenyAccess() throws Throwable {
        ApplicationContext context = mock(ApplicationContext.class);
        GuardResourceAspect aspect = new GuardResourceAspect(context);

        Method testMethod = TestService.class.getMethod("securedMethod3", String.class);
        assertTrue(pointcut.matches(testMethod, TestService.class));

        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(testMethod);
        when(invocation.getArguments()).thenReturn(new Object[]{"myUserId"});
        when(invocation.proceed()).thenReturn(new SubTeamModel("1234-5678", new TeamModel("abcdef")));

        UserDetails defaultUserDetails = buildUserDetailsWithAuthorities(Collections
                .singletonList("ROLE_SUBTEAM_USER_1234-5678"));
        DefaultUserDetailsResolver resolver = mock(DefaultUserDetailsResolver.class);
        when(resolver.resolve(any())).thenReturn(defaultUserDetails);
        when(context.getBean(DefaultUserDetailsResolver.class)).thenReturn(resolver);

        UserDetails fromParamUserDetails = buildUserDetailsWithAuthorities(Collections
                .singletonList("ROLE_TEAM_USER_abcdef"));
        StubUserDetailsResolver stubResolver = mock(StubUserDetailsResolver.class);
        when(stubResolver.resolve(any())).thenReturn(fromParamUserDetails);
        when(context.getBean(StubUserDetailsResolver.class)).thenReturn(stubResolver);

        Object result = aspect.guardResource(invocation);
        assertNotNull(result);
    }

    @Test(expected = AccessDeniedException.class)
    public void when_NoneOfTheUsersHaveAccess_then_DenyAccess() throws Throwable {
        ApplicationContext context = mock(ApplicationContext.class);
        GuardResourceAspect aspect = new GuardResourceAspect(context);

        Method testMethod = TestService.class.getMethod("securedMethod3", String.class);
        assertTrue(pointcut.matches(testMethod, TestService.class));

        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(testMethod);
        when(invocation.getArguments()).thenReturn(new Object[]{"myUserId"});
        when(invocation.proceed()).thenReturn(new SubTeamModel("1234-5678", new TeamModel("abcdef")));

        UserDetails defaultUserDetails = buildUserDetailsWithAuthorities(Collections
                .singletonList("ROLE_TEAM_USER_1234-5678"));
        DefaultUserDetailsResolver resolver = mock(DefaultUserDetailsResolver.class);
        when(resolver.resolve(any())).thenReturn(defaultUserDetails);
        when(context.getBean(DefaultUserDetailsResolver.class)).thenReturn(resolver);

        UserDetails fromParamUserDetails = buildUserDetailsWithAuthorities(Collections
                .singletonList("ROLE_SUBTEAM_USER_abcdef"));
        StubUserDetailsResolver stubResolver = mock(StubUserDetailsResolver.class);
        when(stubResolver.resolve(any())).thenReturn(fromParamUserDetails);
        when(context.getBean(StubUserDetailsResolver.class)).thenReturn(stubResolver);

        Object result = aspect.guardResource(invocation);
        assertNotNull(result);
    }

    @Test
    public void when_methodIsNotGuarded_then_GrantAccess() throws Throwable {
        Method testMethod = TestService.class.getMethod("securedMethod4");
        assertFalse(pointcut.matches(testMethod, TestService.class));
    }

}
