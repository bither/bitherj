package net.bither.bitherj.core;

/**
 * Created by nn on 2014/9/18.
 */
public interface NotificationService {
    void sendBroadcastSyncSPVFinished(boolean isFinished);

    void removeBroadcastSyncSPVFinished();

    void sendLastBlockChange();

    void notificatTx(Address address, Tx tx, Tx.TxNotificationType txNotificationType, long deltaBalance);

    void sendBroadcastPeerState(int numPeers);

    void removeBroadcastPeerState();

    void sendBroadcastAddressLoadCompleteState();

    void removeAddressLoadCompleteState();
}
