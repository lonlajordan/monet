package com.gie.monet.configurations;

import com.gie.monet.models.User;
import com.gie.monet.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfiguration {
    private static String LDAP_PROVIDER_URL;
    private static String LDAP_PROVIDER_HOST;
    private static String LDAP_PROVIDER_PORT;
    private static String LDAP_PROVIDER_DOMAIN_COMPONENT;
    private static String LDAP_PROVIDER_DOMAIN_NAME;

    @Value("${ldap.provider.host}")
    public void setLdapProviderHost(String host){
        SecurityConfiguration.LDAP_PROVIDER_HOST= host;
    }

    @Value("${ldap.provider.port}")
    public void setLdapProviderPort(String port){
        SecurityConfiguration.LDAP_PROVIDER_PORT= port;
    }

    @Value("${ldap.provider.domain.name}")
    public void setLdapProviderDomainName(String name){
        SecurityConfiguration.LDAP_PROVIDER_DOMAIN_NAME = name;
    }

    @Value("${ldap.provider.domain.component}")
    public void setLdapProviderDomainComponent(String component){
        SecurityConfiguration.LDAP_PROVIDER_DOMAIN_COMPONENT = component;
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.csrf().and()
                .sessionManagement()
                .maximumSessions(1).expiredUrl("/").and()
                .invalidSessionUrl("/")
                .and()
                .exceptionHandling()
                .accessDeniedPage("/error/403")
                .and()
                .formLogin()
                .loginPage("/")
                .loginProcessingUrl("/")
                .defaultSuccessUrl("/home", false)
                .failureHandler(new AuthenticationFailureHandler())
                .and()
                .logout()
                .deleteCookies("JSESSIONID")
                .logoutUrl("/logout")
                .logoutSuccessHandler(new AuthenticationLogoutSuccessHandler())
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .and()
                .authorizeRequests()
                .antMatchers("/", "/css/**", "/js/**", "/images/**", "/fonts/**").permitAll()
                .antMatchers("/home").authenticated()
                .antMatchers("/status/**", "/product/**", "/agency/**", "/log/**", "/user/**").hasAuthority("ROLE_GIE_ADMIN")
                .antMatchers("/bank/agency/receive/**").hasAnyAuthority("ROLE_AGENCE_CARTE", "ROLE_AGENCE_CODE")
                .antMatchers("/card/withdraw/**").hasAuthority("ROLE_AGENCE_CARTE")
                .anyRequest().authenticated();
        return http.build();
    }

    @Component
    public static class CustomAuthenticationProvider implements AuthenticationProvider {
        private final UserRepository userRepository;
        private final Environment environment;

        public CustomAuthenticationProvider(UserRepository userRepository, Environment environment) {
            this.userRepository = userRepository;
            this.environment = environment;
        }


        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            String username = authentication.getName();
            String password = (String) authentication.getCredentials();

            User user = userRepository.findByUsername(username);

            if (user == null || !user.getUsername().equalsIgnoreCase(username)) {
                throw new BadCredentialsException("incorrect.username");
            }

            if(Arrays.asList(environment.getActiveProfiles()).contains("production")){
                Hashtable<String, String> properties = new Hashtable<>();
                properties.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
                try {
                    List<InetAddress> addresses = Arrays.asList(InetAddress.getAllByName(SecurityConfiguration.LDAP_PROVIDER_HOST));
                    SecurityConfiguration.LDAP_PROVIDER_URL = addresses.stream().map(address -> "ldap://" + address.getHostAddress() + ":" + SecurityConfiguration.LDAP_PROVIDER_PORT + "/" + SecurityConfiguration.LDAP_PROVIDER_DOMAIN_COMPONENT).collect(Collectors.joining(" "));
                } catch (UnknownHostException e) {
                    SecurityConfiguration.LDAP_PROVIDER_URL = "ldap://" + SecurityConfiguration.LDAP_PROVIDER_DOMAIN_NAME + ":" + SecurityConfiguration.LDAP_PROVIDER_PORT + "/" + SecurityConfiguration.LDAP_PROVIDER_DOMAIN_COMPONENT;
                }
                properties.put(Context.PROVIDER_URL, SecurityConfiguration.LDAP_PROVIDER_URL);
                properties.put(Context.SECURITY_AUTHENTICATION, "simple");
                properties.put(Context.SECURITY_PRINCIPAL, username + "@" + SecurityConfiguration.LDAP_PROVIDER_DOMAIN_NAME);
                properties.put(Context.SECURITY_CREDENTIALS, password);
                try {
                    LdapContext context = new InitialLdapContext(properties, null);
                    context.close();
                } catch (NamingException e) {
                    String error = e.getExplanation() == null ? "" : e.toString().toLowerCase();
                    throw new BadCredentialsException(error.contains("connection refused") ? "connection.refused" : "incorrect.password");
                }
            }
            if(!user.isEnabled()) throw new BadCredentialsException("account.disabled");
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            HttpSession session = attributes.getRequest().getSession(true);
            session.setAttribute("user", user);
            Collection<SimpleGrantedAuthority> authorities = user.getRoles().stream().map(Enum::name).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
            return new UsernamePasswordAuthenticationToken(user.getUsername(), password, authorities);
        }

        @Override
        public boolean supports(Class<?> authentication) {
            return authentication.equals(UsernamePasswordAuthenticationToken.class);
        }

    }

    private static class AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
            String url = "/";
            if(exception != null) {
                String message = exception.getMessage();
                if("incorrect.username".equals(message)){
                    url = "/?error=1";
                }else if("incorrect.password".equals(message)){
                    url = "/?error=2";
                }else if("account.disabled".equals(message)){
                    url = "/?error=3";
                }else if("connection.refused".equals(message)){
                    url = "/?error=4";
                }
            }
            RequestDispatcher dispatcher = request.getRequestDispatcher(url);
            dispatcher.forward(request, response);
        }
    }

    private static class AuthenticationLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
        @Override
        public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
            response.sendRedirect(request.getContextPath() + "/");
        }
    }
}
