/*
 * Copyright (C) 2016 Glyptodon, Inc.
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

package org.glyptodon.guacamole.auth.json.user;

import java.util.Map;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.GuacamoleSecurityException;
import org.glyptodon.guacamole.net.GuacamoleTunnel;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnection;
import org.glyptodon.guacamole.protocol.GuacamoleClientInformation;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;

/**
 * Connection implementation which automatically manages related UserData if
 * the connection is used. Connections which are marked as single-use will
 * be removed from the given UserData such that only the first connection
 * attempt can succeed.
 *
 * @author Michael Jumper
 */
public class UserDataConnection extends SimpleConnection {

    /**
     * The UserData associated with this connection. This UserData will be
     * automatically updated as this connection is used.
     */
    private final UserData data;

    /**
     * The connection entry for this connection within the associated UserData.
     */
    private final UserData.Connection connection;

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
    private static GuacamoleConfiguration getConfiguration(UserData.Connection connection) {

        // Create new configuration for given protocol
        GuacamoleConfiguration config = new GuacamoleConfiguration();
        config.setProtocol(connection.getProtocol());

        // Add all parameter name/value pairs
        Map<String, String> parameters = connection.getParameters();
        if (parameters != null)
            config.setParameters(parameters);

        return config;

    }

    /**
     * Creates a new UserDataConnection which automatically manages the given
     * UserData as the connection is used. The semantics of single-use
     * connections will be automatically and atomically enforced, if enabled
     * for the connection in question.
     *
     * @param data
     *     The UserData that this connection should manage.
     *
     * @param identifier
     *     The identifier associated with this connection within the given
     *     UserData.
     *
     * @param connection
     *     The connection data associated with this connection within the given
     *     UserData.
     */
    public UserDataConnection(UserData data, String identifier, UserData.Connection connection) {
        super(identifier, identifier, getConfiguration(connection));
        this.data = data;
        this.connection = connection;
    }

    @Override
    public GuacamoleTunnel connect(GuacamoleClientInformation info) throws GuacamoleException {

        // Prevent future use immediately upon connect
        if (connection.isSingleUse()) {

            // Deny access if another user already used the connection
            if (data.removeConnection(getIdentifier()) == null)
                throw new GuacamoleSecurityException("Permission denied");

        }

        // Perform connection operation
        return super.connect(info);

    }

}
