
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
import net.bither.bitherj.core.In;
import net.bither.bitherj.core.Out;
import net.bither.bitherj.core.Tx;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

public interface IHDAccountProvider {


    public void addAddress(List<HDAccount.HDAccountAddress> hdAccountAddresses);

    public int issuedIndex(AbstractHD.PathType pathType);

    public int allGeneratedAddressCount(AbstractHD.PathType pathType);

    public void updateIssuedIndex(AbstractHD.PathType pathType, int index);

    public String externalAddress();

    public HashSet<String> getAllAddress();


    public HDAccount.HDAccountAddress addressForPath(AbstractHD.PathType type, int index);


    public List<byte[]> getPubs(AbstractHD.PathType pathType);

    public List<Tx> getUnspentTxs();

    public List<Out> getUnspendOut();

    public List<HDAccount.HDAccountAddress> addTx(Tx tx);

    public void addTxs(List<Tx> txList);

    public List<String> getInAddresses(Tx tx);

    public List<HDAccount.HDAccountAddress> belongAccount(List<String> addresses);

    public int txCount();

    public long getConfirmedBanlance();

    public List<Tx> getUnconfirmedTx();

    public Tx getTxDetailByTxHash(byte[] txHash);

    public List<HDAccount.HDAccountAddress> getSigningAddressesForInputs(List<In> inList);
    public List<Tx> getPublishedTxs();
}
