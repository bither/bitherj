/*
 * Copyright 2014 http://Bither.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.bither.bitherj.db;

import java.util.List;

public interface IHDAccountProvider {
    int addMonitoredHDAccount(String firstAddress, boolean isXrandom, byte[] externalPub, byte[] internalPub);

    boolean hasMnemonicSeed(int hdAccountId);

    public int addHDAccount(String encryptedMnemonicSeed, String encryptSeed
            , String firstAddress, boolean isXrandom, String addressOfPS
            , byte[] externalPub, byte[] internalPub);

    public String getHDFristAddress(int hdSeedId);

    public byte[] getExternalPub(int hdSeedId);

    public byte[] getInternalPub(int hdSeedId);

    public String getHDAccountEncryptSeed(int hdSeedId);

    public String getHDAccountEncryptMnmonicSeed(int hdSeedId);

    public boolean hdAccountIsXRandom(int seedId);

    public List<Integer> getHDAccountSeeds();




}
