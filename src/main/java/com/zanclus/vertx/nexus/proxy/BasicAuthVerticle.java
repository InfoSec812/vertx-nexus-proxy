package com.zanclus.vertx.nexus.proxy;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.eventbus.EventBus;
import io.vertx.core.eventbus.Message;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.impl.LoggerFactory;
import java.util.Base64;

/**
 *
 * @author <a href="https://github.com/InfoSec812">Deven Phillips</a>
 */
public class BasicAuthVerticle extends AbstractVerticle {

    @Override
    public void start() throws Exception {
        Logger log = LoggerFactory.getLogger(this.getClass());
        final String target = context.config().getString("targetHost", "192.168.1.70");
        final Integer port = context.config().getInteger("targetPort", 8081);
        EventBus eb = vertx.eventBus();
        eb.consumer("proxy.login.do", (Message<JsonObject> event) -> {
            log.error("Recieved proxy login event.");
            String username = event.body().getString("username");
            String password = event.body().getString("password");
            JsonObject response = new JsonObject();
            if (username==null || password==null) {
                response.put("error", "Username and/or password values are null.");
                response.put("status", 0);
                log.error("Sending error response.");
                eb.send("proxy.login.response", response);
            } else {
                String credentials = username+":"+password;
                String basicAuth = Base64.getEncoder().encodeToString(credentials.getBytes());
                final String url = String.format("http://%1$s:%2$d/nexus/service/local/users/%3$s", target, port, username);
                vertx
                    .createHttpClient(new HttpClientOptions())
                    .request(HttpMethod.GET, url)
                    .putHeader("Authorization", "Basic "+basicAuth)
                    .putHeader("Accept", "application/json")
                    .handler(res -> {
                        response.put("status", res.statusCode());
                        response.put("response", res.statusMessage());
                        log.error("Sending login response: "+url+": "+res.statusMessage());
                        res.bodyHandler(buffer -> {
                            String jsonResponse = new String(buffer.getBytes());
                            response.put("userinfo", new JsonObject(jsonResponse));
                            event.reply(response);
                        });
                    })
                    .end();
            }
        });
    }
}