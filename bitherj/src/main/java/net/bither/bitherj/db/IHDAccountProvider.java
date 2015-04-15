
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

import net.bither.bitherj.core.AbstractHD;
import net.bither.bitherj.core.HDAccount;
import net.bither.bitherj.core.Tx;

import java.util.HashMap;
import java.util.List;

public interface IHDAccountProvider {


    public void addExternalAddress(List<HDAccount.HDAccountAddress> hdAccountAddresses);

    public void addInternalAddress(List<HDAccount.HDAccountAddress> hdAccountAddresses);

    public int issuedExternalIndex();

    public int issuedInternalIndex();

    public int allGeneratedInternalAddressCount();

    public int allGeneratedExternalAddressCount();

    public void updateIssuedInternalIndex(int index);

    public void updateIssuedExternalIndex(int index);

    public String externalAddress();

    public HDAccount.HDAccountAddress addressForPath(AbstractHD.PathType type, int index);

    public List<Integer> getHDAccountSeeds();

    public List<HDAccount.HDAccountAddress> getAllHDAddress();

    public List<Tx> getUnspentTxs();

    public List<HDAccount.HDAccountAddress> addTx(Tx tx);

    public void addTxs(List<Tx> txList);


}
