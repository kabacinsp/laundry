package pl.kabacinsp.laundry.user.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;
import pl.kabacinsp.laundry.user.security.AccessDeniedHandlerImpl;
import pl.kabacinsp.laundry.user.security.AuthenticationProviderImpl;
import pl.kabacinsp.laundry.user.security.AuthenticationSuccessHandleImpl;
import pl.kabacinsp.laundry.user.security.LogoutSuccessHandlerImpl;
import pl.kabacinsp.laundry.user.security.jwt.AuthTokenFilter;
import pl.kabacinsp.laundry.user.service.UserDetailsServiceImpl;

@Configuration
@EnableMethodSecurity
// @Order(-20)
public class WebSecurityConfig {

  @Autowired private UserDetailsServiceImpl customUserDetailsService;

  @Bean
  public AuthTokenFilter authenticationJwtTokenFilter() {
    return new AuthTokenFilter();
  }

  @Bean
  public SecurityFilterChain securityFilterChain(
      HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
    MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);

    http.csrf(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests(
            (auth) ->
                auth.requestMatchers(mvcMatcherBuilder.pattern("/auth/**"))
                    .permitAll()
                    .requestMatchers(mvcMatcherBuilder.pattern("/test/**"))
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
        .authenticationProvider(authenticationProvider())
        .addFilterBefore(
            authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    return http.build();
  }

  @Bean
  public AccessDeniedHandler accessDeniedHandler() {
    return new AccessDeniedHandlerImpl();
  }

  @Bean
  public LogoutSuccessHandler logoutSuccessHandler() {
    return new LogoutSuccessHandlerImpl();
  }

  @Bean
  public AuthenticationSuccessHandler loginSuccessHandler() {
    return new AuthenticationSuccessHandleImpl();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public DaoAuthenticationProvider authenticationProvider() {
    final DaoAuthenticationProvider bean = new AuthenticationProviderImpl();
    bean.setUserDetailsService(customUserDetailsService);
    bean.setPasswordEncoder(passwordEncoder());
    return bean;
  }

  @Bean
  public AuthenticationManager authManager(HttpSecurity http) throws Exception {
    return http.getSharedObject(AuthenticationManagerBuilder.class)
        .authenticationProvider(authenticationProvider())
        .build();
  }

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer(HandlerMappingIntrospector introspector) {
    MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
    return (web) -> web.ignoring().requestMatchers(mvcMatcherBuilder.pattern("/resources/**"));
  }
}
