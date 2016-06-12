/*
 *
 *  * Copyright 2014 http://Bither.net
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *    http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package net.bither.bitherj.api;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * Created by songchenwen on 15/1/23.
 */
public class TrustCert {
    private InputStream input;
    private char[] password;
    private String type;

    private TrustCert() {

    }

    public TrustCert(InputStream input, char[] password, String type) {
        this.input = input;
        this.password = password;
        this.type = type;
    }

    public KeyStore getKeyStore() throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        KeyStore localTrustStore = KeyStore.getInstance(type);
        if (localTrustStore == null) {
            return null;
        }
        try {
            localTrustStore.load(input, password);
        } finally {
            input.close();
        }
        return localTrustStore;
    }
}
