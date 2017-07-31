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

public interface IHDAccountAddressProvider {


    void addAddress(List<HDAccount.HDAccountAddress> hdAccountAddresses);

    int issuedIndex(int hdAccountId, AbstractHD.PathType pathType);

    int allGeneratedAddressCount(int hdAccountId, AbstractHD.PathType pathType);

    void updateIssuedIndex(int hdAccountId, AbstractHD.PathType pathType, int index);

    String externalAddress(int hdAccountId);


    HashSet<String> getBelongAccountAddresses(int hdAccountId, List<String> addressList);
    HashSet<String> getBelongAccountAddresses(List<String> addressList);
    Tx updateOutHDAccountId(Tx tx);
    int getRelatedAddressCnt(List<String> addresses);
    List<Integer> getRelatedHDAccountIdList(List<String> addresses);


    HDAccount.HDAccountAddress addressForPath(int hdAccountId, AbstractHD.PathType type, int index);

    List<byte[]> getPubs(int hdAccountId, AbstractHD.PathType pathType);

    List<HDAccount.HDAccountAddress> belongAccount(int hdAccountId, List<String> addresses);

    void updateSyncdComplete(int hdAccountId, HDAccount.HDAccountAddress address);

    void setSyncedNotComplete();

    int unSyncedAddressCount(int hdAccountId);

    void updateSyncedForIndex(int hdAccountId, AbstractHD.PathType pathType, int index);

    List<HDAccount.HDAccountAddress> getSigningAddressesForInputs(int hdAccountId, List<In> inList);

    int hdAccountTxCount(int hdAccountId);

    long getHDAccountConfirmedBalance(int hdAccountId);

    List<Tx> getHDAccountUnconfirmedTx(int hdAccountId);

    long sentFromAccount(int hdAccountId, byte[] txHash);

    List<Tx> getTxAndDetailByHDAccount(int hdAccountId, int page);

    List<Tx> getTxAndDetailByHDAccount(int hdAccountId);

    List<Out> getUnspendOutByHDAccount(int hdAccountId);

    List<Tx> getRecentlyTxsByAccount(int hdAccountId, int greaterThanBlockNo, int limit);

    int getUnspendOutCountByHDAccountWithPath(int hdAccountId, AbstractHD.PathType pathType);

    List<Out> getUnspendOutByHDAccountWithPath(int hdAccountId, AbstractHD.PathType pathType);

    int getUnconfirmedSpentOutCountByHDAccountWithPath(int hdAccountId, AbstractHD.PathType
            pathType);

    List<Out> getUnconfirmedSpentOutByHDAccountWithPath(int hdAccountId, AbstractHD.PathType pathType);

    boolean requestNewReceivingAddress(int hdAccountId);

    List<Out> getUnspentOutputByBlockNo(long BlockNo, int hdSeedId);
}
