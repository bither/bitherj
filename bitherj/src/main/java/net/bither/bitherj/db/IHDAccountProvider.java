
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

import net.bither.bitherj.core.Tx;

import java.util.HashMap;
import java.util.List;

public interface IHDAccountProvider {

    public int addHDKey(String encryptSeed, String encryptHdSeed
            , String firstAddress, boolean isXrandom, String addressOfPS
            , byte[] externalPub, byte[] internalPub);

    public int externalIssuedIndex();

    public int internalIssuedIndex();

    public byte[] getExternalPub();

    public byte[] getInternalPub();

    public String externalAddress();

    public List<HashMap<String, byte[]>> getAddressPub();

    public List<Tx> getUnspentTxs();

    public void addTx(Tx tx);

    public void addTxs(List<Tx> txList);

    public String getEncryptSeed(int hdSeedId);

    public String getEncryptHDSeed(int hdSeedId);


}
