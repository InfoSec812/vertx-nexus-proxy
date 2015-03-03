package com.zanclus.vertx.nexus.proxy;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.impl.LoggerFactory;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;
import javax.sql.DataSource;

/**
 * A worker {@link io.vertx.core.Verticle} which performs database interactions
 * @author <a href="https://github.com/InfoSec812">Deven Phillips</a>
 */
public class DbWorkerVerticle extends AbstractVerticle {

    private static final Logger LOG = LoggerFactory.getLogger(DbWorkerVerticle.class);

    @Override
    public void start() throws Exception {
        listenForValidationEvents();
        listenForNewTokenEvents();
        listenForDeleteEvents();
        listenForTokenListEvent();
        listenForUserDeleteEvent();
        listenForUserListEvent();
    }

    /**
     * Register a consumer for token creation events
     */
    private void listenForNewTokenEvents() {
        vertx.eventBus().consumer("proxy.create.token", (Message<String> token) -> {
            DataSource ds = context.get("dbConnectionPool");
            JsonObject response = new JsonObject();
            try (   Connection c = ds.getConnection();
                PreparedStatement s = c.prepareStatement("INSERT INTO user_tokens (username, token) VALUES (?, ?)")) {
                String uuid = UUID.randomUUID().toString();
                String username = token.body();
                s.setString(1, username);
                s.setString(2, uuid);
                if (s.executeUpdate()==1) {
                    response.put("token", uuid);
                    response.put("username", username);
                } else {
                    response.put("error", "Unknown error");
                }
            } catch (SQLException sqle) {
                response.put("error", sqle.getLocalizedMessage());
                token.reply(response);
            }
        });
    }

    /**
     * Register a consumer for token validation events
     */
    private void listenForValidationEvents() {
        vertx.eventBus().consumer("proxy.validate.token", (Message<String> token) -> {
            DataSource ds = context.get("dbConnectionPool");
            JsonObject response = new JsonObject();
            try (   Connection c = ds.getConnection();
                PreparedStatement s = c.prepareStatement("SELECT username FROM user_tokens WHERE token=?")) {
                s.setString(1, token.body());
                try (ResultSet r = s.executeQuery()) {
                    r.beforeFirst();
                    if (r.next()) {
                        // We got a result from the DB, reply with a valid username
                        response.put("username", r.getString(1));
                    } else {
                        // We did not get a result from the DB, reply with an response.
                        response.put("error", "Unknown token");
                    }
                } catch (SQLException sqle) {
                    response.put("error", sqle.getLocalizedMessage());
                }
            } catch (SQLException sqle) {
                response.put("error", sqle.getLocalizedMessage());
            }
            token.reply(response);
        });
    }

    /**
     * Register a consume for token deletion events
     */
    private void listenForDeleteEvents() {
        vertx.eventBus().consumer("proxy.delete.token", (Message<JsonObject> token) -> {
            DataSource ds = context.get("dbConnectionPool");
            JsonObject response = new JsonObject();
            try (   Connection c = ds.getConnection();
                PreparedStatement s = c.prepareStatement("DELETE FROM user_tokens WHERE username=? AND token=?")) {
                s.setString(1, token.body().getString("username"));
                s.setString(2, token.body().getString("token"));
                if (s.executeUpdate()==1) {
                    response.put("success", "true");
                } else {
                    response.put("error", "Unknown error");
                }
            } catch (SQLException sqle) {
                response.put("error", sqle.getLocalizedMessage());
            }
            token.reply(response);
       });
    }

    /**
     * Register a consumer for token list events.
     */
    private void listenForTokenListEvent() {
        vertx.eventBus().consumer("proxy.token.list", (Message<String> msg) -> {
            DataSource ds = context.get("dbConnectionPool");
            JsonObject response = new JsonObject();
            String username = msg.body();
            try (   Connection c = ds.getConnection();
                    PreparedStatement s = c.prepareStatement("SELECT token FROM user_token WHERE username=?")) {
                s.setString(1, username);
                try (ResultSet r = s.executeQuery()) {
                    r.beforeFirst();
                    response.put("username", username);
                    JsonArray tokens = new JsonArray();
                    while (r.next()) {
                        tokens.add(r.getString(1));
                    }
                    response.put("tokens", tokens);
                } catch (SQLException sqle) {
                    response.put("error", sqle.getLocalizedMessage());
                }
            } catch (SQLException sqle) {
                response.put("error", sqle.getLocalizedMessage());
            }
            msg.reply(response);
        });
    }

    /**
     * Register a consumer to listen for user list events
     */
    private void listenForUserListEvent() {
        vertx.eventBus().consumer("proxy.user.list", (Message<Void> msg) -> {
            DataSource ds = context.get("dbConnectionPool");
            JsonObject response = new JsonObject();
            try (   Connection c = ds.getConnection();
                    PreparedStatement s = c.prepareStatement("SELECT DISTINCT user FROM user_token")) {
                try (ResultSet r = s.executeQuery()) {
                    r.beforeFirst();
                    JsonArray users = new JsonArray();
                    while (r.next()) {
                        users.add(r.getString(1));
                    }
                    response.put("users", users);
                } catch (SQLException sqle) {
                    response.put("error", sqle.getLocalizedMessage());
                }
            } catch (SQLException sqle) {
                response.put("error", sqle.getLocalizedMessage());
            }
            msg.reply(response);
        });
    }

    /**
     * Register a consumer ti listen for user delete events
     */
    private void listenForUserDeleteEvent() {
        vertx.eventBus().consumer("proxy.user.delete", (Message<String> msg) -> {
            DataSource ds = context.get("dbConnectionPool");
            JsonObject response = new JsonObject();
            String username = msg.body();
            try (   Connection c = ds.getConnection();
                    PreparedStatement s = c.prepareStatement("DELETE FROM user_token WHERE username=?")) {
                s.setString(1, username);
                if (s.executeUpdate()>0) {
                    response.put("success", "true");
                } else {
                    response.put("error", String.format("No tokens for user '%s' found.", username));
                }
            } catch (SQLException sqle) {
                response.put("error", sqle.getLocalizedMessage());
            }
            msg.reply(response);
        });
    }
}
