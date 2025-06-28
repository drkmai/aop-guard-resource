# 🛡️ GuardResource – Method-Level Authorization with AOP for Spring-based applications

**GuardResource** is a lightweight Java library using AOP in a Spring Context to provide declarative method-level access control. With an annotation you can set multiple scope/role definitions per method. It Integrates with Spring Security’s `UserDetails` and `GrantedAuthority` and custom user resolution with pluggable resolvers.

---

## 📦 Installation

Maven repository and Gradle distribution are still pending so feel free to compile it yourself and plug it in.

## Basic Usage

Apply the `@GuardResource` annotation to any method you want to secure:

```java
@GuardResource(scopes = {
    @ScopeDefinition(scopeType = "subteam", roles = {"USER"}),
    @ScopeDefinition(scopeType = "team", roles = {"ADMIN"})
})
public Object securedMethod() {
    return objectThatShouldBeSecured;
}
```

You can also use a custom resolver to extract the user identity dynamically:

```java
@GuardResource(scopes = {
    @ScopeDefinition(
        scopeType = "team",
        roles = {"ADMIN"},
        userIdParam = "myUserId",
        userResolver = MyCustomUserResolver.class
    )
})
public Object secureWithCustomResolver(String myUserId) {
    return myOtherSecuredObject;
}
```

---

## ⚙️ Configuration

Make sure Spring scans the beans from the library:

```java
@SpringBootApplication(scanBasePackages = {"com.your.package","com.derekmai.aop.guard.resource"})
public class YourSpringApplication {
}
```

Your User model should implement Spring Security's UserDetails, providing a fully functional getAuthorities.

```
Authority String format_
ROLE_{SCOPE_TYPE}_{ROLE_TYPE}_{RESOURCE_ID}
For example:
ROLE_GROUP_ADMIN_b8a082a4-b58e-4537-823f-31e6774ab149
```

Any Entity you want to protect needs to implement `Accessible` and `Identifiable` along with get methods that match the Scope accessor.
```java
public class TeamModel implements Accessible, Identifiable {

    private String id;

    public TeamModel(String id) {
        this.id = id;
    }

    @Override
    public Object getId() {
        return id;
    }
}

public class SubTeamModel implements Accessible, Identifiable {

    private String id;
    private TeamModel teamModel;

    public SubTeamModel(String id,TeamModel team) {
        this.id = id;
        this.teamModel = team;
    }

    @Override
    public Object getId() {
        return id;
    }

    /* getter method name should follow the pattern get+{ScopeType} */
    public TeamModel getTeam() {
        return teamModel;
    }

    /* getter method name should follow the pattern get+{ScopeType} */
    public SubTeamModel getSubteam() {
        return this;
    }
}

```


For having a custom UserDetailsResolver, you just have to implement UserDetailsResolverInterface

```java
@Component
@RequiredArgsConstructor
public class UserRepositoryDetailsResolver implements UserDetailsResolver {

  private final UserRepository userRepository;

  @Override
  public UserDetails resolve(Object userId) {
    return userRepository.findById((UUID)userId).get();
  }
}
```

You can concatenate methods that utilise `@GuardResource` to validate in a single flow different kind of access from the same user. If any of them fails, access to the resource is denied because the user does not have permission in the whole chain.

```java
@Service
@RequiredArgsConstructor
public class TeamService {

  private final TeamRepository teamRepository;

  @GuardResource(scopes = {
      @ScopeDefinition(scopeType = "team", roles = {"USER"})
  })
  public TeamModel getTeam(UUID teamId) {
    return teamRepository.findById(teamId);
  }
}

@Service
@RequiredArgsConstructor
public class SubteamService {

  private final TeamService teamService;
  private final SubteamRepository subteamRepository;

  @GuardResource(scopes = {
      @ScopeDefinition(scopeType = "team", roles = {"USER", "ADMIN"}),
      @ScopeDefinition(scopeType = "subteam", roles = {"ADMIN"})
  })
  public List<Subteam> getSubteamsByTeam(UUID teamId) {
    /* The team Service is guarded so we'll check for user permissions in there.
     * Execution will continue only if the user has sufficient permissions to obtain said team object.
     */
    TeamModel team = teamService.getTeam(teamId);
    return subteamRepository.findTeam(team);
  }
}
```

---

## 📋 Requirements

- Java 8+
- Spring Framework

---

## 📄 License

MIT License © 2025 – [Derek Mai]
