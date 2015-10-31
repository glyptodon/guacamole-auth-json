/*
 * Copyright (C) 2015 Glyptodon LLC
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

package org.glyptodon.guacamole.auth.json;

import com.google.inject.Inject;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.environment.Environment;

/**
 * Service for retrieving configuration information regarding the JSON
 * authentication provider.
 *
 * @author Michael Jumper
 */
public class ConfigurationService {

    /**
     * The Guacamole server environment.
     */
    @Inject
    private Environment environment;

    /**
     * The encryption key to use for all decryption.
     */
    private static final ByteArrayProperty JSON_ENCRYPTION_KEY = new ByteArrayProperty() {

        @Override
        public String getName() {
            return "json-encryption-key";
        }

    };

    /**
     * Returns the symmetric encryption key which will be used to encrypt all
     * JSON data and should be used to decrypt any received JSON data. This is
     * dictated by the "json-encryption-key" property specified within
     * guacamole.properties.
     *
     * @return
     *     The key which should be used to decrypt received JSON data.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed, or if the
     *     "json-encryption-key" property is missing.
     */
    public byte[] getEncryptionKey() throws GuacamoleException {
        return environment.getRequiredProperty(JSON_ENCRYPTION_KEY);
    }

}
