package com.derekmai.aop.guard.resource.config;

import com.derekmai.aop.guard.resource.GuardResourceAspect;
import org.aopalliance.intercept.MethodInterceptor;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration class that sets up Aspect-Oriented Programming (AOP) support
 * for guarding resources annotated with {@link com.derekmai.aop.guard.resource.GuardResource}.
 * <p>
 * This configuration defines a {@link DefaultPointcutAdvisor} bean that matches any method annotated
 * with {@code @GuardResource} within the package prefix specified by the {@code guard.service-package} property.
 * The matched methods are intercepted by the logic defined in {@link GuardResourceAspect}.
 * </p>
 *
 * <p>
 * This class is only loaded if {@link GuardResourceAspect} is present in the classpath.
 * </p>
 *
 * <p>
 * To take advantage of this configuration, ensure your application defines the {@code guard.service-package}
 * property to indicate where the guarded components are located.
 * </p>
 *
 * @see GuardResourceAspect
 * @see com.derekmai.aop.guard.resource.GuardResource
 */
@Configuration
@Aspect
@ConditionalOnClass(GuardResourceAspect.class)
public class AopConfig {

    private final Logger log = LoggerFactory.getLogger(AopConfig.class);

    private final GuardResourceAspect guardResourceAspect;

    @Value("${guard.service-package:}")
    private String packagePrefix;

    public AopConfig(GuardResourceAspect guardResourceAspect) {
        this.guardResourceAspect = guardResourceAspect;
    }

    /**
     * Defines a {@link DefaultPointcutAdvisor} that applies {@link GuardResourceAspect}
     * to all methods annotated with {@link com.derekmai.aop.guard.resource.GuardResource}
     * withing specified packages by {@code guard.service-package} property.
     * <p>
     * This advisor utilizes AspectJ for identifying methods inside the configured package that are annotated with
     * {@code @GuardResource} annotation and applies the defined interception in {@link GuardResourceAspect}.
     * </p>
     *
     * @return a {@link DefaultPointcutAdvisor} configured with the corresponding pointcut and advice.
     */
    @Bean
    public DefaultPointcutAdvisor guardResourceAdvisor() {
        log.debug("Package prefix used for GuardResource within pointcut: {}", packagePrefix);
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression(
                "within(" + packagePrefix + "..*) && @annotation(com.derekmai.aop.guard.resource.GuardResource)"
        );
        MethodInterceptor advice = guardResourceAspect::guardResource;
        return new DefaultPointcutAdvisor(pointcut, advice);
    }
}
