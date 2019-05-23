/*
 *
 *  Copyright 2014 http://Bither.net
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * /
 */

package net.bither.bitherj.db;

import java.util.List;

public interface IDesktopAddressProvider {

    int addHDKey(String encryptedMnemonicSeed, String encryptHdSeed,
                 String firstAddress, boolean isXrandom, String addressOfPS
            , byte[] externalPub, byte[] internalPub);

    void addHDMPub(List<byte[]> externalPubs, List<byte[]> internalPubs);

    List<byte[]> getExternalPubs();

    List<byte[]> getInternalPubs();

    boolean isHDSeedFromXRandom(int hdSeedId);

    String getEncryptMnemonicSeed(int hdSeedId);

    String getEncryptHDSeed(int hdSeedId);

    String getHDMFristAddress(int hdSeedId);

    List<Integer> getDesktopKeyChainSeed();
}
