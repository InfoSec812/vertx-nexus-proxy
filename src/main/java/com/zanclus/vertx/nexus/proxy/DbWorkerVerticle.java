package com.zanclus.vertx.nexus.proxy;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.eventbus.Message;
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
    }

    private void listenForNewTokenEvents() {
        vertx.eventBus().consumer("proxy.create.token", (Message<JsonObject> token) -> {
            DataSource ds = context.get("dbConnectionPool");
            JsonObject response = new JsonObject();
            try (   Connection c = ds.getConnection();
                PreparedStatement s = c.prepareStatement("INSERT INTO user_tokens (username, token) VALUES (?, ?)")) {
                String uuid = UUID.randomUUID().toString();
                String username = token.body().getString("username");
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
                    token.reply(response);
                } catch (SQLException sqle) {
                    response.put("error", sqle.getLocalizedMessage());
                    token.reply(response);
                }
            } catch (SQLException sqle) {
                response.put("error", sqle.getLocalizedMessage());
                token.reply(response);
            }
        });
    }
}
