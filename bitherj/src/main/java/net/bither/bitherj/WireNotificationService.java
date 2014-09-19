package net.bither.bitherj;

import net.bither.bitherj.core.Address;
import net.bither.bitherj.core.AddressManager;
import net.bither.bitherj.core.PeerManager;
import net.bither.bitherj.core.NotificationService;

/**
 * Created by nn on 2014/9/18.
 */
public class WireNotificationService {
    public static void wire(NotificationService notificationService) {
        Address.NOTIFICATION_SERVICE = notificationService;
        AddressManager.NOTIFICATION_SERVICE = notificationService;
        BitherjApplication.NOTIFICATION_SERVICE = notificationService;
        PeerManager.NOTIFICATION_SERVICE = notificationService;
    }
}
