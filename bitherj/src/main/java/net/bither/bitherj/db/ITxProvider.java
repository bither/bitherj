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

import net.bither.bitherj.core.In;
import net.bither.bitherj.core.Out;
import net.bither.bitherj.core.Tx;
import net.bither.bitherj.utils.Sha256Hash;

import java.util.HashMap;
import java.util.List;

public interface ITxProvider {
    public List<Tx> getTxAndDetailByAddress(String address);

    public List<Tx> getTxAndDetailByAddress(String address, int page);

    public List<Tx> getPublishedTxs();

    public Tx getTxDetailByTxHash(byte[] txHash);

    public long sentFromAddress(byte[] txHash, String address);

    public boolean isExist(byte[] txHash);

    public void add(Tx txItem);

    public void addTxs(List<Tx> txItems);

    public void remove(byte[] txHash);


    public boolean isAddressContainsTx(String address, Tx txItem);

    public boolean isTxDoubleSpendWithConfirmedTx(Tx tx);

    public List<String> getInAddresses(Tx tx);


    public void confirmTx(int blockNo, List<byte[]> txHashes);

    public void unConfirmTxByBlockNo(int blockNo);

    public List<Tx> getUnspendTxWithAddress(String address);

    public List<Out> getUnspendOutWithAddress(String address);

    // for calculate balance
    public long getConfirmedBalanceWithAddress(String address);

    public List<Tx> getUnconfirmedTxWithAddress(String address);

//    public List<Out> getUnSpendOutCanSpendWithAddress(String address);
//
//    public List<Out> getUnSpendOutButNotConfirmWithAddress(String address);

    public int txCount(String address);

    public long totalReceive(String address);

    public void txSentBySelfHasSaw(byte[] txHash);

    public List<Out> getOuts();

//    public List<Out> getUnSpentOuts();

    public List<In> getRelatedIn(String address);

    public List<Tx> getRecentlyTxsByAddress(String address, int greateThanBlockNo, int limit);

//    public List<Long> txInValues(byte[] txHash);

    // do not check tx 's dependency fo now
    public HashMap<Sha256Hash, Tx> getTxDependencies(Tx txItem);

    // complete in signature
    public void completeInSignature(List<In> ins);

    public int needCompleteInSignature(String address);

    public void clearAllTx();

    byte[] isIdentify(Tx tx);
}
