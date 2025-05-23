package com.marcelo.helpdesk.config;

import java.util.Arrays;
import java.util.List;
import org.springframework.http.HttpMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.web.filter.CorsFilter;

import com.marcelo.helpdesk.secutiry.JWTAuthenticationFilter;
import com.marcelo.helpdesk.secutiry.JWTAuthorizationFilter;
import com.marcelo.helpdesk.secutiry.JWTUtil;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecutiryConfig extends WebSecurityConfigurerAdapter {

    private static final String[] PUBLIC_MATCHERS = { "/h2-console/**", "/login" };

    @Autowired
    private Environment env;

    @Autowired
    private JWTUtil jwtUtil;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        if (Arrays.asList(env.getActiveProfiles()).contains("test")) {
            http.headers(headers -> headers.frameOptions().disable());
        }

        http
          .cors()                                 
          .and()
          .csrf(csrf -> csrf.disable())
          .addFilter(new JWTAuthenticationFilter(authenticationManager(), jwtUtil))
          .addFilter(new JWTAuthorizationFilter(authenticationManager(), jwtUtil, userDetailsService))
          .authorizeRequests(auth -> auth
		  	  .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
              .antMatchers(PUBLIC_MATCHERS).permitAll()		  
              .anyRequest().authenticated()
          )
          .sessionManagement(sm -> sm
              .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
          );
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
            .passwordEncoder(bCryptPasswordEncoder());
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowedOrigins(List.of("https://helpdesk-deploy.vercel.app"));
		config.setAllowedMethods(Arrays.asList("POST", "GET", "PUT", "DELETE", "OPTIONS"));
		config.setAllowedHeaders(List.of("*"));
		config.setExposedHeaders(List.of("Authorization"));
		config.setAllowCredentials(true); 

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", config);
		return source;
	}

    @Bean
    @Order(0)
    public FilterRegistrationBean<CorsFilter> corsFilterRegistrationBean(
        CorsConfigurationSource corsConfigurationSource
    ) {
        FilterRegistrationBean<CorsFilter> bean =
            new FilterRegistrationBean<>(new CorsFilter(corsConfigurationSource));
        bean.setOrder(0);
        return bean;
    }
}