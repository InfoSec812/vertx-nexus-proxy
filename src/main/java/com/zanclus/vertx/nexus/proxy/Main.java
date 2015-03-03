package com.zanclus.vertx.nexus.proxy;

import com.beust.jcommander.JCommander;
import com.zanclus.vertx.nexus.proxy.config.Config;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.AsyncResult;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Verticle;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.Message;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.impl.LoggerFactory;
import io.vertx.ext.apex.Router;
import io.vertx.ext.apex.RoutingContext;
import io.vertx.ext.apex.handler.SessionHandler;
import io.vertx.ext.apex.handler.StaticHandler;
import io.vertx.ext.apex.sstore.LocalSessionStore;
import io.vertx.ext.apex.sstore.SessionStore;
import java.util.Map;
import java.util.Properties;
import org.apache.commons.dbcp2.BasicDataSource;

/**
 *
 * @author <a href="https://github.com/InfoSec812">Deven Phillips</a>
 */
public class Main extends AbstractVerticle {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        LOG.debug("Starting");
        JsonObject config = parseArguments(args);
        DeploymentOptions dOpts = new DeploymentOptions();
        dOpts.setConfig(config);
        Vertx.vertx().deployVerticle(new Main(), dOpts);
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
        JsonObject config = new JsonObject(((Map<String, Object>)cfg.getParams()));
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
        LOG.error("Config:\n\n"+context.config().encodePrettily()+"\n\n");
        context.put("dbConnectionPool", createDatabaseConnectionPool(context.config()));

        // Deploy database worker verticle
        vertx.deployVerticle("", new DeploymentOptions().setWorker(true).setMultiThreaded(true), res0 -> {
            
            // After the database worker verticle is loaded, load the BasicAuthVerticle
            vertx.deployVerticle(new BasicAuthVerticle(), res1 -> {
                configureHttpRequestRouter();
            });
        });
    }

    private void configureHttpRequestRouter() {
        // Create a session handler which uses cookies to maintain state across HTTP requests.
        SessionStore store = LocalSessionStore.create(vertx);
        SessionHandler sessionHandler = SessionHandler.create(store);
        
        // Create a Router which will route requeests to the appropriate haandlers
        Router router = Router.router(vertx);
        
        // Attach the session handler to the Router
        router.route().handler(sessionHandler);
        
        // TODO: Configure a route which will server static files

        // Route to handle serving static content for the proxy management web application
        router.route(HttpMethod.GET, "/nexus-proxy/").handler(StaticHandler.create());
        // Route for getting a list of all users
        router.route(HttpMethod.GET, "/mexus-proxy/api/user").handler(ctx -> {
            UserInfo info = this.processAuth((JsonObject)ctx.session().data().get("user_info"));
            if (info.isAdmin()) {
                vertx.eventBus().send("proxy.user.list", null, (AsyncResult<Message<JsonObject>> reply) -> {
                    ctx .response()
                        .setStatusCode(200)
                        .putHeader("Content-Type", "application/json")
                        .end(reply.result().body().encodePrettily());
                });
            } else {
                ctx.response().setStatusCode(401).setStatusMessage("Must be admin to list users.").end();
            }
        });
        // Route for getting user details
        router.route(HttpMethod.GET, "/nexus-proxy/api/user/:username").handler(ctx -> {
            UserInfo info = this.processAuth((JsonObject)ctx.session().data().get("user_info"));
            String username = ctx.request().params().get("username");
            if (info.isAdmin() || (info.isAuthenticated() && info.username.contentEquals(username))) {
                vertx.eventBus().send("proxy.user.list", null, (AsyncResult<Message<JsonObject>> reply) -> {
                    ctx .response()
                        .setStatusCode(200)
                        .putHeader("Content-Type", "application/json")
                        .end(reply.result().body().encodePrettily());
                });
            } else {
                ctx.response().setStatusCode(401).setStatusMessage("Must be admin to view other users.").end();
            }
        });
        // Route for DELETEing all of a user's tokens
        router.route(HttpMethod.DELETE, "/nexus-proxy/api/user/:username").handler(ctx -> {
            UserInfo info = this.processAuth((JsonObject)ctx.session().data().get("user_info"));
            String username = ctx.request().params().get("username");
            if (info.isAdmin() || (info.isAuthenticated() && info.username.contentEquals(username))) {
                vertx.eventBus().send("proxy.user.delete", null, (AsyncResult<Message<JsonObject>> reply) -> {
                    ctx .response()
                        .setStatusCode(200)
                        .putHeader("Content-Type", "application/json")
                        .end(reply.result().body().encodePrettily());
                });
            } else {
                ctx.response().setStatusCode(401).setStatusMessage("Must be admin to delete users.").end();
            }
        });
        // Route for DELETEing a single user token
        router.route(HttpMethod.DELETE, "/nexus-proxy/api/user/:username/:token").handler(ctx -> {
            UserInfo info = this.processAuth((JsonObject)ctx.session().data().get("user_info"));
            String username = ctx.request().params().get("username");
            if (info.isAdmin() || (info.isAuthenticated() && info.username.contentEquals(username))) {
                JsonObject params = new JsonObject()
                        .put("username", info.getUsername())
                        .put("token", ctx.request().params().get("token"));
                vertx.eventBus().send("proxy.delete.token", params, (AsyncResult<Message<JsonObject>> reply) -> {
                    ctx .response()
                        .setStatusCode(200)
                        .putHeader("Content-Type", "application/json")
                        .end(reply.result().body().encodePrettily());
                });
            } else {
                ctx.response().setStatusCode(401).setStatusMessage("Must be admin to delete tokens from other users.").end();
            }
        });
        // Route for CREATEing a new user token
        router.route(HttpMethod.POST, "/nexus-proxy/api/user/:username").handler(ctx -> {
            UserInfo info = this.processAuth((JsonObject)ctx.session().data().get("user_info"));
            String username = ctx.request().params().get("username");
            if (info.isAdmin() || (info.isAuthenticated() && info.username.contentEquals(username))) {
                vertx.eventBus().send("proxy.delete.token", username, (AsyncResult<Message<JsonObject>> reply) -> {
                    ctx .response()
                        .setStatusCode(200)
                        .putHeader("Content-Type", "application/json")
                        .end(reply.result().body().encodePrettily());
                });
            } else {
                ctx.response().setStatusCode(401).setStatusMessage("Must be admin to create tokens for other users.").end();
            }
        });
        // Route to proxy requests to the nexus server
        router.routeWithRegex("^/nexus/.*").handler(ctx -> {
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
        vertx.createHttpServer().requestHandler(router::accept).listen(context.config().getInteger("proxyPort"), context.config().getString("proxyHost"));
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

    private UserInfo processAuth(JsonObject userInfo) {
        UserInfo info = new UserInfo();
        if (userInfo!=null && userInfo.getJsonObject("data")!=null && userInfo.getJsonObject("data").getString("userId")!=null) {
            info.setUsername(userInfo.getJsonObject("data").getString("userId"));
            if (userInfo.getJsonObject("data")!=null && userInfo.getJsonObject("data").getJsonArray("roles")!=null) {
                JsonArray roles = userInfo.getJsonObject("data").getJsonArray("roles");
                if (roles.contains("nx-admin")) {
                    info.setAdmin(true);
                }
            }
            info.setAuthenticated(true);
        }
        
        return info;
    }

    private class UserInfo {
        private boolean authenticated = false;
        private boolean admin = false;
        private String username = null;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public boolean isAdmin() {
            return admin;
        }

        public boolean isAuthenticated() {
            return authenticated;
        }

        public void setAdmin(boolean admin) {
            this.admin = admin;
        }

        public void setAuthenticated(boolean authenticated) {
            this.authenticated = authenticated;
        }
    }
}
