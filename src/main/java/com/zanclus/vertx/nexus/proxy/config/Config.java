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

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import java.io.File;
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
        if (this.proxyHost==null) {
            this.proxyHost = "127.0.0.1";
        }
        if (this.proxyPort==null) {
            this.proxyPort = 8080;
        }
        if (this.targetHost==null) {
            this.targetHost = "127.0.0.1";
        }
        if (this.targetPort==null) {
            this.targetPort = 8081;
        }
        if (this.maxDbConnections==null) {
            this.maxDbConnections = 10;
        }
        if (this.minDbConnections==null) {
            this.minDbConnections = 2;
        }
        if (this.rutHeader==null) {
            this.rutHeader = "REMOTE_USER";
        }
        if (this.dbPath==null) {
            this.dbPath = "/tmp/nexus-tokens";
        }
    }

    @Parameter(description = "This help message", names = {"-h", "--help"}, help = true)
    private boolean help = false;

    @Parameter(description = "The hostname or IP address on which the proxy to listen for incomming requests.", names = {"-l", "--proxy-host"})
    private String proxyHost;

    @Parameter(description = "Port on which the proxy will listen for incoming requests.", names = {"-p", "--proxy-port"})
    private Integer proxyPort;

    @Parameter(description = "The hostname or IP address of the application to be proxied.", names = {"-t", "--target-host"})
    private String targetHost;
    
    @Parameter(description = "Port of the application to be proxied.", names = {"-r", "--target-port"})
    private Integer targetPort;

    @Parameter(description = "The name of the header which should be set on proxied requests.", names = {"-m", "--rut-header"})
    private String rutHeader;

    @Parameter(description = "The path at which to store the HSQLDB files", names = {"-d", "--db-path"})
    private String dbPath;
    
    @Parameter(description = "The maximum number of concurrent database connections.", names = {"-a", "--max-db-connections"})
    private Integer maxDbConnections;
    
    @Parameter(description = "The minimum number of concurrent database connections to keep in the connection pool.", names = {"-o", "--min-db-connections"})
    private Integer minDbConnections;
}
