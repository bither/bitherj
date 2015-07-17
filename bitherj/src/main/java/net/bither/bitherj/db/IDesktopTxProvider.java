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

import net.bither.bitherj.core.*;
import org.omg.CORBA.PUBLIC_MEMBER;

import java.util.HashSet;
import java.util.List;

/**
 * Created by nn on 15/6/15.
 */
public interface IDesktopTxProvider {
    public void addAddress(List<DesktopHDMAddress> address);

    public int maxHDMAddressPubIndex();

    public String externalAddress();

    public boolean hasAddress();

    public long getHDAccountConfirmedBanlance(int hdSeedId);

    public HashSet<String> getBelongAccountAddresses(List<String> addressList);

    public void updateIssuedIndex(AbstractHD.PathType pathType, int index);

    public int issuedIndex(AbstractHD.PathType pathType);

    public int allGeneratedAddressCount(AbstractHD.PathType pathType);

    public void updateSyncdForIndex(AbstractHD.PathType pathType, int index);

    public void updateSyncdComplete(DesktopHDMAddress address);

    public List<Tx> getHDAccountUnconfirmedTx();

    public List<HDMAddress.Pubs> getPubs(AbstractHD.PathType pathType);

    public int getUnspendOutCountByHDAccountWithPath(int hdAccountId, AbstractHD.PathType pathType);

    public List<Out> getUnspendOutByHDAccountWithPath(int hdAccountId, AbstractHD.PathType pathType);

    public DesktopHDMAddress addressForPath(DesktopHDMKeychain keychain, AbstractHD.PathType type, int index);

    public List<DesktopHDMAddress> getSigningAddressesForInputs(DesktopHDMKeychain keychain, List<In> inList);

    public List<DesktopHDMAddress> belongAccount(DesktopHDMKeychain keychain, List<String> addresses);

    public List<Out> getUnspendOutByHDAccount(int hdAccountId);

    public int unSyncedAddressCount();
}
