package id.bikushoppu.filter;

import java.util.Date;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import id.bikushoppu.config.AuthorizationConfig;
import id.bikushoppu.util.JwtTokenUtil;
import reactor.core.publisher.Mono;

@Component
public class AuthorizationFitler implements GlobalFilter {

    @Autowired
    private AuthorizationConfig authorizationConfig;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        if (!authorizationConfig.getWhitelistedPath().contains(path)) {
            String authorization = Optional.ofNullable(request.getHeaders().getFirst("Authorization")).orElse("");
            String token = authorization.replace("Bearer ", "");
            if (!"".equals(token) && new Date().before(this.jwtTokenUtil.getExpirationDateFromToken(token))) {
                //get role for the path on redis. initilize redis value once bean has been created, check hook lifecycle
                if (this.jwtTokenUtil.getRoles(token).contains("RL-ADMIN")) {
                    return chain.filter(exchange);
                }
            }
        } else {
            return chain.filter(exchange);
        }
        return exchange.getResponse().setComplete();
    }
}
