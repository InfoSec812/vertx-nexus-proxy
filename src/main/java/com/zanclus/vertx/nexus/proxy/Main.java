package com.zanclus.vertx.nexus.proxy;

import com.beust.jcommander.JCommander;
import com.zanclus.vertx.nexus.proxy.config.Config;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.AsyncResult;
import io.vertx.core.Verticle;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.core.eventbus.Message;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.impl.LoggerFactory;
import io.vertx.ext.apex.core.Router;
import io.vertx.ext.apex.core.RoutingContext;
import java.util.Map;
import java.util.Properties;
import org.apache.commons.beanutils.BeanMap;
import org.apache.commons.dbcp2.BasicDataSource;

/**
 *
 * @author <a href="https://github.com/InfoSec812">Deven Phillips</a>
 */
public class Main extends AbstractVerticle {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        LOG.debug("Starting");
        VertxOptions opts = new VertxOptions(parseArguments(args));
        Vertx.vertx(opts).deployVerticle(new Main());
    }

    /**
     * Parse command-line arguments and store them in a {@link JsonObject} instance
     * @param args An array containing all of the command-line arguments passed to the application on startup
     * @return A {@link JsonObject} containing the configuration
     */
    private static JsonObject parseArguments(String[] args) {
        Config cfg = new Config();
        JCommander commander = new JCommander(cfg, args);
        cfg.fillDefaults();
        if (cfg.isHelp()) {
            commander.usage("nexus-auth-proxy");
            System.exit(0);
        }
        Map cfgMap = new BeanMap(cfg);
        JsonObject config = new JsonObject(cfgMap);
        LOG.debug("Config:\n\n"+config.encodePrettily()+"\n\n");
        return config;
    }

    /**
     * Create a new instance of {@link BasicDataSource} for using an embedded HSQLDB for storing user->token mappings
     * @param config The application's JSON configuration object.
     * @return An instance of {@link BasicDataSource} which connects to an embedded HSQLDB database engine
     */
    private BasicDataSource createDatabaseConnectionPool(JsonObject config) {
        String url = "jdbc:hsqldb:file:"+config.getString("dbPath");
        BasicDataSource ds = new BasicDataSource();
        Properties dbProps = new Properties();
        ds.addConnectionProperty("username", "SA");
        ds.addConnectionProperty("password", "");
        ds.addConnectionProperty("url", url);
        ds.addConnectionProperty("driverClassName", "org.hsqldb.jdbc.JDBCDriver");
        ds.addConnectionProperty("shutdown", "true");
        ds.setMinIdle(config.getInteger("minDbConnections"));
        ds.setMaxTotal(config.getInteger("maxDbConnections"));
        ds.setTimeBetweenEvictionRunsMillis(60000);
        return ds;
    }

    /**
     * The main {@link Verticle} for this proxy application.
     * @throws Exception
     */
    @Override
    public void start() throws Exception {
        Logger log = LoggerFactory.getLogger(this.getClass());
        context.put("dbConnectionPool", createDatabaseConnectionPool(context.config()));
        vertx.deployVerticle(new BasicAuthVerticle(), res -> {
            Router router = Router.router(vertx);
            // router.route("/nexus-proxy/").handler(StaticH)
            router.routeWithRegex("^/nexus/.*").handler((RoutingContext ctx) -> {
                ctx.request().headers().remove(context.config().getString("rutHeader"));
                if (HttpMethod.GET.equals(ctx.request().method())) {
                    String authHeader = ctx.request().headers().get("Authorization");
                    String type = authHeader.split(" ")[0];
                    String credentials = authHeader.split(" ")[1];
                    if (type.toUpperCase().contentEquals("BEARER")) {
                        // Verify bearer token and get associated user
                        vertx.eventBus().send("proxy.validate.token", credentials, (AsyncResult<Message<JsonObject>> event) -> {
                            JsonObject result = event.result().body();
                            if (result.getString("error")!=null) {
                                LOG.warn(result.getString("error"));
                                ctx.request().headers().remove(context.config().getString("rutHeader"));
                            } else {
                                ctx.request().headers().add(context.config().getString("rutHeader"), result.getString("username"));
                            }
                            sendProxyRequest(ctx);
                        });
                    } else {
                        ctx.request().headers().remove(context.config().getString("rutHeader"));
                        sendProxyRequest(ctx);
                    }
                }
            });
        });
    }

    private void sendProxyRequest(RoutingContext ctx) {
        String urlWithQueryParams = ctx.request().uri().split("/", 3)[4];
        String uri = "http://"
                + context.config().getString("targetHost")
                + ":"
                + context.config().getString("targetPort")
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
}
