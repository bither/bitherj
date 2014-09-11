# Why did Bither switch from Bitcoinj to Bitherj ?

We stopped using Bitcoinj since Bither Android v0.0.9, and switched to Bitherj (a brand new Java implemented library of the Bitcoin protocol developped by our team).

It was a tough choice, and we didn't want to "reinvent the wheel" too. But cause the "fragileness" of Bitcoinj, we had to develop Bitherj to provide better solutions for our users.

The major problems of Bitcoinj are:

  1. Structure:
  
  For SPV thin wallet, normal user does not require all transactions on blockchain, and they only care about their own (and dependent) transactions.

  So when designing the thin wallet structure, we should consider using relational models other than serialized models for data storage.

  But in Bitcoinj, no matter the SPV headers or wallet files, all are saved as serialized file.

  2. Performance:

  Because of the Bitcoinj's file structure, all file IO are using Google serializable to read all and write all. It is not an issue for the one who only has one wallet, one address and serveral transactions (e.g. Bitcoin-Wallet), but for users with multiple wallets, multiple addresses and more transactions, that can be a problem, sometimes even a "disaster".

  Also with the special design of the Confidential model, when a new block is recevied, all addresses' transactions in each wallet file will be updated, even when the new block are not related to any addresses' transactions. Bitcoinj will use Google serializable to read the whole wallet files into the memory, update all data, and then use Google serializable to write the whole wallet files back to the file system.

  This is the core reason of the performance issue.

  3. Error:

  The structure cause the performance issue, if the issue is only limited to performance, we can still endure it. But the problem is, this performance bottleneck may cause many kinds of running errors, and sometimes can even be a "disaster".

  Maybe having realized this performance issue, the author of Bitcoinj designed two isolated writing thread, one for higher priority, and the other for lower priority. This special design may cause more problems, such as wallet files are not synced with blockchain header file, transactions' status in wallet are not synchronized, and many transactions are frequently switched between right and wrong status. Maybe the wallet file are written correctly this time, but modified to wrong value in next delayed writing queue.

  As a developer, you can not trust wether a value is reliable or not, and the only thing you can do is using other ways to check the status of wallets and transactions. If you find status errors, you may try to fix the data or even reset the whole blockchain.

  Without reading the source code and trying to implement Bitcoin wallet, you may have no idea about these. But for the developers of MultiBit and our team, we all have to write so many codes to bypass the Bitcoinj's "trick", you can read the source code of MultiBit and Bither for more details. (Special thanks to the developers of MultiBit. We have learned a lot from their source code, and also we can confirm the disaster in [this url]( http://www.reddit.com/r/Bitcoin/comments/22gt4r/major_mulitibit_bug_btc_gone_it_cost_me_all_of_my/) is not caused by MultiBit.)

Because the structure can cause severe performance issue, and the performance issue may cause many "strange" errors. Also all these issues and errors are clear, can be reproduced, but difficult to solve based on current Bitcoinj's structure. Finanly, we decided to redesign and develop Bitherj.

Bitherj's structure is relational (based on SQLite engine), it is a more stable, more reliable and higher performance Java implementation of Bitcoin protocol. We are working hard to keep Bitherj compatible with Bitheri (our Objective-C version of Bitherj), and we will try to improve these two library as possible as we can.

If you are also a Bitcoin wallet developers, and find some "strange" problems when developping with Bitcoinj, you can contact us. We may already encounter and try to fix the same problems, our experiences may be helpful to you.

If you are a normal user of any Bitcoin SPV thin wallets, you should know the reason of fixing the transactions' data and resetting the blockchain. The most important thing is to keep your private keys safe, because for Bitcoin, private key means everything.

Thanks for reading!

Best Regards,

Bither Team
