/*
 * Copyright (C) 2018 Glyptodon, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
 * NOTE: The code implemented provided here for establishing connections is
 * based upon the connect() function of the SimpleConnection class, part of the
 * "guacamole-ext" library, which is part of Apache Guacamole. The relevant
 * code has been modified to suit the purposes of this extension.
 */

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.glyptodon.guacamole.auth.json.connection;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.io.GuacamoleReader;
import org.apache.guacamole.io.GuacamoleWriter;
import org.apache.guacamole.net.GuacamoleSocket;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.InetGuacamoleSocket;
import org.apache.guacamole.net.SSLGuacamoleSocket;
import org.apache.guacamole.net.SimpleGuacamoleTunnel;
import org.apache.guacamole.net.auth.GuacamoleProxyConfiguration;
import org.apache.guacamole.protocol.ConfiguredGuacamoleSocket;
import org.apache.guacamole.protocol.GuacamoleClientInformation;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.glyptodon.guacamole.auth.json.user.UserData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service which provides a centralized means of establishing connections,
 * tracking/joining active connections, and retrieving associated data.
 *
 * @author Michael Jumper
 */
@Singleton
public class ConnectionService {

    /**
     * Logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(ConnectionService.class);

    /**
     * The Guacamole server environment.
     */
    @Inject
    private Environment environment;

    /**
     * Mapping of the unique IDs of active connections (as specified within the
     * UserData.Connection object) to the underlying connection ID (as returned
     * via the Guacamole protocol handshake). Only connections with defined IDs
     * are tracked here.
     */
    private final ConcurrentHashMap<String, String> activeConnections =
            new ConcurrentHashMap<String, String>();

    /**
     * Generates a new GuacamoleConfiguration from the associated protocol and
     * parameters of the given UserData.Connection.
     *
     * @param connection
     *     The UserData.Connection whose protocol and parameters should be used
     *     to construct the new GuacamoleConfiguration.
     *
     * @return
     *     A new GuacamoleConfiguration generated from the associated protocol
     *     and parameters of the given UserData.Connection.
     */
    public GuacamoleConfiguration getConfiguration(UserData.Connection connection) {

        GuacamoleConfiguration config = new GuacamoleConfiguration();

        // Set connection ID if joining an active connection
        String primaryConnection = connection.getPrimaryConnection();
        if (primaryConnection != null) {

            // If no such active connection actually exists, allow things to
            // fail cleanly by using a non-existent connection ID
            String id = activeConnections.get(primaryConnection);
            if (id == null)
                id = UUID.randomUUID().toString();

            config.setConnectionID(id);

        }

        // Otherwise, require protocol
        else
            config.setProtocol(connection.getProtocol());

        // Add all parameter name/value pairs
        Map<String, String> parameters = connection.getParameters();
        if (parameters != null)
            config.setParameters(parameters);

        return config;

    }

    /**
     * Establishes a connection to guacd using the information associated with
     * the given connection object. The resulting connection will be provided
     * the given client information during the Guacamole protocol handshake.
     *
     * @param connection
     *     The connection object describing the nature of the connection to be
     *     established.
     *
     * @param info
     *     Information associated with the connecting client.
     *
     * @return
     *     A fully-established GuacamoleTunnel.
     *
     * @throws GuacamoleException
     *     If an error occurs while connecting to guacd, or if permission to
     *     connect is denied.
     */
    public GuacamoleTunnel connect(UserData.Connection connection,
            GuacamoleClientInformation info) throws GuacamoleException {

        // Retrieve proxy configuration from environment
        GuacamoleProxyConfiguration proxyConfig = environment.getDefaultGuacamoleProxyConfiguration();

        // Get guacd connection parameters
        String hostname = proxyConfig.getHostname();
        int port = proxyConfig.getPort();

        final ConfiguredGuacamoleSocket socket;

        // Determine socket type based on required encryption method
        switch (proxyConfig.getEncryptionMethod()) {

            // If guacd requires SSL, use it
            case SSL:
                socket = new ConfiguredGuacamoleSocket(
                    new SSLGuacamoleSocket(hostname, port),
                    getConfiguration(connection), info
                );
                break;

            // Connect directly via TCP if encryption is not enabled
            case NONE:
                socket = new ConfiguredGuacamoleSocket(
                    new InetGuacamoleSocket(hostname, port),
                    getConfiguration(connection), info
                );
                break;

            // Abort if encryption method is unknown
            default:
                throw new GuacamoleServerException("Unimplemented encryption method.");

        }

        // If the current connection is not being tracked (no ID) just return
        // a normal, non-tracking tunnel
        final String id = connection.getId();
        if (id == null)
            return new SimpleGuacamoleTunnel(socket);

        // If the current connection is intended to be tracked (an ID was
        // provided), but a connection is already in progress with that ID,
        // log a warning that the original connection will no longer be tracked
        final String connectionID = socket.getConnectionID();
        String activeConnection = activeConnections.put(id, connectionID);
        if (activeConnection != null)
            logger.warn("A connection with ID \"{}\" is already in progress, "
                    + "but another attempt to use this ID has been made. The "
                    + "original connection will no longer be joinable.", id);

        // Return a tunnel which automatically tracks the active connection
        return new SimpleGuacamoleTunnel(new GuacamoleSocket() {

            @Override
            public GuacamoleReader getReader() {
                return socket.getReader();
            }

            @Override
            public GuacamoleWriter getWriter() {
                return socket.getWriter();
            }

            @Override
            public void close() throws GuacamoleException {
                activeConnections.remove(id, connectionID);
                socket.close();
            }

            @Override
            public boolean isOpen() {
                return socket.isOpen();
            }

        });

    }

}
