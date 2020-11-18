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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
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
import org.apache.guacamole.token.TokenFilter;

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
            new ConcurrentHashMap<>();

    /**
     * Mapping of the connection IDs of joinable connections (as returned via
     * the Guacamole protocol handshake) to the Collection of tunnels shadowing
     * those connections.
     */
    private final ConcurrentHashMap<String, Collection<GuacamoleTunnel>> shadowers =
            new ConcurrentHashMap<>();

    /**
     * Generates a new GuacamoleConfiguration from the associated protocol and
     * parameters of the given UserData.Connection. If the configuration cannot
     * be generated (because a connection is being joined by that connection is
     * not actually active), null is returned.
     *
     * @param connection
     *     The UserData.Connection whose protocol and parameters should be used
     *     to construct the new GuacamoleConfiguration.
     *
     * @return
     *     A new GuacamoleConfiguration generated from the associated protocol
     *     and parameters of the given UserData.Connection, or null if the
     *     configuration cannot be generated.
     */
    public GuacamoleConfiguration getConfiguration(UserData.Connection connection) {

        GuacamoleConfiguration config = new GuacamoleConfiguration();

        // Set connection ID if joining an active connection
        String primaryConnection = connection.getPrimaryConnection();
        if (primaryConnection != null) {

            // Verify that the connection being joined actually exists
            String id = activeConnections.get(primaryConnection);
            if (id == null)
                return null;

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
     * Closes all tunnels within the given connection. If a GuacamoleException
     * is thrown by any tunnel during closure, that exception is ignored.
     *
     * @param tunnels
     *     The Collection of tunnels to close.
     */
    private void closeAll(Collection<GuacamoleTunnel> tunnels) {

        for (GuacamoleTunnel tunnel : tunnels) {
            try {
                tunnel.close();
            }
            catch (GuacamoleException e) {
                logger.debug("Failure to close tunnel masked by closeAll().", e);
            }
        }

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
            GuacamoleClientInformation info, Map<String, String> tokens) throws GuacamoleException {

        // Retrieve proxy configuration from environment
        GuacamoleProxyConfiguration proxyConfig = environment.getDefaultGuacamoleProxyConfiguration();

        // Get guacd connection parameters
        String hostname = proxyConfig.getHostname();
        int port = proxyConfig.getPort();

        // Generate and verify connection configuration
        GuacamoleConfiguration filteredConfig = getConfiguration(connection);

        if (filteredConfig == null) {
            logger.debug("Configuration for connection could not be "
                    + "generated. Perhaps the connection being joined is not "
                    + "active?");
            throw new GuacamoleResourceNotFoundException("No such connection");
        }

        // Apply tokens to config parameters
        new TokenFilter(tokens).filterValues(filteredConfig.getParameters());

        // Determine socket type based on required encryption method
        final ConfiguredGuacamoleSocket socket;
        switch (proxyConfig.getEncryptionMethod()) {

            // If guacd requires SSL, use it
            case SSL:
                socket = new ConfiguredGuacamoleSocket(
                    new SSLGuacamoleSocket(hostname, port),
                        filteredConfig, info
                );
                break;

            // Connect directly via TCP if encryption is not enabled
            case NONE:
                socket = new ConfiguredGuacamoleSocket(
                    new InetGuacamoleSocket(hostname, port),
                        filteredConfig, info
                );
                break;

            // Abort if encryption method is unknown
            default:
                throw new GuacamoleServerException("Unimplemented encryption method.");

        }

        final GuacamoleTunnel tunnel;

        // If the current connection is not being tracked (no ID) just use a
        // normal, non-tracking tunnel
        final String id = connection.getId();
        if (id == null)
            tunnel = new SimpleGuacamoleTunnel(socket);

        // Otherwise, create a tunnel with proper tracking which can be joined
        else {

            // Allow connection to be joined
            final String connectionID = socket.getConnectionID();
            final Collection<GuacamoleTunnel> existingTunnels = shadowers.putIfAbsent(connectionID,
                    Collections.synchronizedList(new ArrayList<>()));

            // Duplicate connection IDs cannot exist
            assert(existingTunnels == null);

            // If the current connection is intended to be tracked (an ID was
            // provided), but a connection is already in progress with that ID,
            // log a warning that the original connection will no longer be tracked
            String activeConnection = activeConnections.put(id, connectionID);
            if (activeConnection != null)
                logger.warn("A connection with ID \"{}\" is already in progress, "
                        + "but another attempt to use this ID has been made. The "
                        + "original connection will no longer be joinable.", id);

            // Return a tunnel which automatically tracks the active connection
            tunnel = new SimpleGuacamoleTunnel(new GuacamoleSocket() {

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

                    // Stop connection from being joined further
                    activeConnections.remove(id, connectionID);

                    // Close all connections sharing the closed connection
                    Collection<GuacamoleTunnel> tunnels = shadowers.remove(connectionID);
                    if (tunnels != null)
                        closeAll(tunnels);

                    socket.close();

                }

                @Override
                public boolean isOpen() {
                    return socket.isOpen();
                }

            });

        }

        // Track tunnels which join connections, such that they can be
        // automatically closed when the joined connection closes
        String joinedConnection = filteredConfig.getConnectionID();
        if (joinedConnection != null) {

            // Track shadower of joined connection if possible
            Collection<GuacamoleTunnel> tunnels = shadowers.get(joinedConnection);
            if (tunnels != null)
                tunnels.add(tunnel);

            // Close this tunnel in ALL CASES if the joined connection has
            // closed. Note that it is insufficient to simply check whether the
            // retrieved Collection is null here, as it may have been removed
            // after retrieval. We must ensure that the tunnel is closed in any
            // case where it will not automatically be closed due to the
            // closure of the shadowed connection.
            if (!shadowers.containsKey(joinedConnection))
                tunnel.close();

        }

        return tunnel;

    }

}
