/**
 * Copyright 2013 Jim Burton.
 * Copyright 2014 Andreas Schildbach
 * <p/>
 * Licensed under the MIT license (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://opensource.org/licenses/mit-license.php
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.bither.bitherj.crypto;

/**
 * <p>Exception to provide the following to {@link }:</p>
 * <ul>
 * <li>Provision of encryption / decryption exception</li>
 * </ul>
 * <p>This base exception acts as a general failure mode not attributable to a specific cause (other than
 * that reported in the exception message). Since this is in English, it may not be worth reporting directly
 * to the user other than as part of a "general failure to parse" response.</p>
 */
public class KeyCrypterException extends RuntimeException {
    private static final long serialVersionUID = -4441989608332681377L;

    public KeyCrypterException(String s) {
        super(s);
    }

    public KeyCrypterException(String s, Throwable throwable) {
        super(s, throwable);
    }
}
