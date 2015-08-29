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

import net.bither.bitherj.core.AbstractHD;
import net.bither.bitherj.core.DesktopHDMAddress;
import net.bither.bitherj.core.DesktopHDMKeychain;
import net.bither.bitherj.core.HDMAddress;
import net.bither.bitherj.core.In;
import net.bither.bitherj.core.Out;
import net.bither.bitherj.core.Tx;

import java.util.HashSet;
import java.util.List;

/**
 * Created by nn on 15/6/15.
 */
public interface IDesktopTxProvider {
    void addAddress(List<DesktopHDMAddress> address);

    int maxHDMAddressPubIndex();

    String externalAddress();

    boolean hasAddress();

    long getHDAccountConfirmedBanlance(int hdSeedId);

    HashSet<String> getBelongAccountAddresses(List<String> addressList);

    void updateIssuedIndex(AbstractHD.PathType pathType, int index);

    int issuedIndex(AbstractHD.PathType pathType);

    int allGeneratedAddressCount(AbstractHD.PathType pathType);

    void updateSyncdForIndex(AbstractHD.PathType pathType, int index);

    void updateSyncdComplete(DesktopHDMAddress address);

    List<Tx> getHDAccountUnconfirmedTx();

    List<HDMAddress.Pubs> getPubs(AbstractHD.PathType pathType);

    int getUnspendOutCountByHDAccountWithPath(int hdAccountId, AbstractHD.PathType pathType);

    List<Out> getUnspendOutByHDAccountWithPath(int hdAccountId, AbstractHD.PathType pathType);

    DesktopHDMAddress addressForPath(DesktopHDMKeychain keychain, AbstractHD.PathType type, int index);

    List<DesktopHDMAddress> getSigningAddressesForInputs(DesktopHDMKeychain keychain, List<In> inList);

    List<DesktopHDMAddress> belongAccount(DesktopHDMKeychain keychain, List<String> addresses);

    List<Out> getUnspendOutByHDAccount(int hdAccountId);

    int unSyncedAddressCount();
}
