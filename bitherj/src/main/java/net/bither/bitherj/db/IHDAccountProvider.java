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

import java.util.HashSet;
import java.util.List;

public interface IHDAccountProvider {


    public void addAddress(List<HDAccount.HDAccountAddress> hdAccountAddresses);

    public int issuedIndex(AbstractHD.PathType pathType);

    public int allGeneratedAddressCount(AbstractHD.PathType pathType);

    public void updateIssuedIndex(AbstractHD.PathType pathType, int index);

    public String externalAddress();


    public HashSet<String> getBelongAccountAddresses(List<String> addressList);


    public HDAccount.HDAccountAddress addressForPath(AbstractHD.PathType type, int index);

    public List<byte[]> getPubs(AbstractHD.PathType pathType);

    public List<HDAccount.HDAccountAddress> belongAccount(List<String> addresses);

    public void updateSyncdComplete(HDAccount.HDAccountAddress address);

    public void setSyncdNotComplete();

    public int unSyncedAddressCount();

    public void updateSyncdForIndex(AbstractHD.PathType pathType, int index);

    public List<HDAccount.HDAccountAddress> getSigningAddressesForInputs(List<In> inList);

    public int hdAccountTxCount();

    public long getHDAccountConfirmedBanlance(int hdAccountId);

    public List<Tx> getHDAccountUnconfirmedTx();

    public long sentFromAccount(int hdAccountId, byte[] txHash);

    public List<Tx> getTxAndDetailByHDAccount(int page);

    public List<Tx> getTxAndDetailByHDAccount();

    public List<Out> getUnspendOutByHDAccount(int hdAccountId);

    public List<Tx> getRecentlyTxsByAccount(int greateThanBlockNo, int limit);

    public int getUnspendOutCountByHDAccountWithPath(int hdAccountId, AbstractHD.PathType pathType);

    public List<Out> getUnspendOutByHDAccountWithPath(int hdAccountId, AbstractHD.PathType pathType);
}
