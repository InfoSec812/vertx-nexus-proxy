package com.zanclus.vertx.nexus.proxy;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.impl.LoggerFactory;
import io.vertx.ext.apex.core.Router;
import io.vertx.ext.apex.core.RoutingContext;

/**
 *
 * @author <a href="">Deven Phillips</a>
 */
public class Main extends AbstractVerticle {
    public static void main(String[] args) {
        // TODO: Read cli params and create JsonObject for configuration settings
        Vertx.vertx().deployVerticle(new Main());
    }

    /**
     *
     * @throws Exception
     */
    @Override
    public void start() throws Exception {
        Logger log = LoggerFactory.getLogger(this.getClass());
        if (context.config().getString("rut_header")==null) {
            context.config().put("rut_header", "REMOTE_USER");
        }
        if (context.config().getString("target_host")==null) {
            context.config().put("target_host", "127.0.0.1");
        }
        if (context.config().getString("target_port")==null) {
            context.config().put("target_port", 8081);
        }
        if (context.config().getString("proxy_host")==null) {
            context.config().put("proxy_host", "127.0.0.1");
        }
        if (context.config().getString("proxy_port")==null) {
            context.config().put("proxy_port", 8080);
        }
        vertx.deployVerticle(new BasicAuthVerticle(), res -> {
            Router router = Router.router(vertx);
            // router.route("/nexus-proxy/").handler(StaticH)
            router.routeWithRegex("^/nexus/.*").handler((RoutingContext ctx) -> {
                ctx.request().headers().remove(context.config().getString("rut_header"));
                if (HttpMethod.GET.equals(ctx.request().method())) {
                    String authHeader = ctx.request().headers().get("Authorization");
                    String type = authHeader.split(" ")[0];
                    String credentials = authHeader.split(" ")[1];
                    if (type.toUpperCase().contentEquals("BEARER")) {
                        // TODO: Verify bearer token and get associated username
                        // ctx
                        //    .request()
                        //    .headers()
                        //    .add(context.config()
                        //                .getString("rut_header")
                        //                .toUpperCase(), "username");
                    }
                    String urlWithQueryParams = ctx.request().uri().split("/", 3)[4];
                    String uri = "http://"
                                    + context.config().getString("target_host")
                                    + ":"
                                    + context.config().getString("target_port")
                                    + urlWithQueryParams;
                    HttpClient client = vertx.createHttpClient(new HttpClientOptions());
                    final HttpClientRequest req = client.request(ctx.request().method(), uri);
                    req.headers().addAll(ctx.request().headers());
                    ctx.request().bodyHandler(body -> {
                        req.end(body.copy());
                        req.handler(response -> {
                            ctx.response().headers().addAll(response.headers());
                            ctx.response().setStatusCode(response.statusCode());
                            response.bodyHandler(resBody -> {
                                ctx.response().end(resBody.copy());
                            });
                        });
                    });
                }
            });
        });
    }
}
