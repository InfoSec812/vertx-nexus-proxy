package com.zanclus.vertx.nexus.proxy.config;

/*
 * #%L
 * nexus-auth-proxy
 * %%
 * Copyright (C) 2015 Zanclus Consulting
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/gpl-3.0.html>.
 * #L%
 */

import com.beust.jcommander.DynamicParameter;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import java.util.HashMap;
import java.util.Map;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Bean for storing configuration options. Also used by JCommander to parse command-line arguments
 * @author <a href="https://github.com/InfoSec812/">Deven Phillips</a>
 */
@Data
@NoArgsConstructor
@Parameters(separators = " =")
public class Config {

    public void fillDefaults() {
        if (params.get("proxyHost")==null) {
            params.put("proxyHost", "127.0.0.1");
        }
        if (params.get("proxyPort")==null) {
            params.put("proxyPort",8080);
        }
        if (params.get("targetHost")==null) {
            params.put("targetHost","192.168.1.70");
        }
        if (params.get("targetPort")==null) {
            params.put("targetPort",8081);
        }
        if (params.get("maxDbConnections")==null) {
            params.put("maxDbConnections",10);
        }
        if (params.get("minDbConnections")==null) {
            params.put("minDbConnections",2);
        }
        if (params.get("rutHeader")==null) {
            params.put("rutHeader","REMOTE_USER");
        }
        if (params.get("dbPath")==null) {
            params.put("dbPath","/tmp/nexus-tokens");
        }
    }

    @Parameter(description = "This help message", names = {"-h", "--help"}, help = true)
    private boolean help = false;

    @DynamicParameter(names = "-C", description = "parameters as key-value pairs")
    private Map<String, Object> params = new HashMap<>();
}
