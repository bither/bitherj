# "Sensitive" Information in Memory

The informations are different!
Although we can transform both the bitcoin private key and the transaction data to pure text, they are totally different. The private key is vital, and we should keep it safe as possible as we can, but the transaction data does not matter.

So we should use and store the informations in different ways and security levels, even in memory.

For example, in Java, we usually write codes like this:
String password = "bither.net";

After finish using the password, we can also set the password to other value or even null.
password = "8btc.com";
password = null;

Normally these codes are ok in many circumstance. But when we want to store "sensitive" informations (private keys, passwords...), String is not a safe choice, because :
> Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes [String objects unsuitable for storing security sensitive information such as user passwords](http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx).

That means, although you can set the password to any values ("bitcoin.org", "bitcointalk.org"....), all strings ("bither.net", "8btc.com", "bitcoin.org", "bitcointalk.org") will stay in memory.

Normally it is not so "dangerous", because it is difficult to "steal" information from your memory. Unless you faced another incident like "OpenSSL HeartBleed". Hackers may use this kind of flaws to steal data from your memory. If there are "sensitive" information in those data (e.g. private keys), BOOM!

"Normally it's ok, the odds are rare" is not the reason of writing insecured codes.

What is the correct way to do such things?

You should use `CharSequence` (`Char Array`), and after finish using the sensitive information, using loop to overwirte the content (e.g. blank or random value). The lifecycle of the "sensitive" information should be as short as possible.

If you have read some source codes of Java or Android, now you may know why they use `CharSequence` (`Char Array`) instead of String in many places (e.g. `EditText`).

You can take a look at our implementation of CharSequence for further understanding the correct method to use and store the sensitive informations: [SecureCharSequence](https://github.com/bither/bitherj/blob/master/bitherj/src/main/java/net/bither/bitherj/crypto/SecureCharSequence.java)

The advantage of using SecureCharSequence is : even when next "OpenSSL HeartBleed" happens, your bitcoins are still a little bit safer than others.

We had posted issues for the following projects :
* blockchain.info : https://github.com/blockchain/My-Wallet-Android/issues/10
* Bitcoin Wallet : https://github.com/schildbach/bitcoin-wallet/issues/179
* Mycelium : https://github.com/mycelium-com/wallet/issues/135
