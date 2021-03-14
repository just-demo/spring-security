package demo.config;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.cloud.security.oauth2.gateway.TokenRelayGatewayFilterFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RoutesConfiguration {
    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route(p -> p.path("/resource-server/**")
                        .filters(f -> f.stripPrefix(1))
                        .uri("lb://resource-server"))
                .build();
    }

    /**
     * Alternatively this could be applied per each route as
     * .filters(f -> f.filter(filterFactory.apply()))
     */
    @Bean
    public GlobalFilter tokenRelayFilter(TokenRelayGatewayFilterFactory filterFactory) {
        return (exchange, chain) -> filterFactory.apply().filter(exchange, chain);
    }
}
