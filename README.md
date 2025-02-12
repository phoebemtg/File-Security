**Account Setup: **
When InitUser is called, we first need to generate two key pairs: one for digital signatures and one for RSA
encryption. We add the public keys to the keystore under UUIDs generated from getUUID("ds", username) and
getUUID("pke", username) respectively. Next, we generate a 16-byte root key using Argon2Key(password, salt, 16) ,
where salt is 32 random bytes. From this, we can derive keys for symmetric encrypting and authenticating
using HashKDF(rootKey, []byte("enc-key")) and HashKDF(rootKey, []byte("mac-key")) . We can finish by
encrypt/tagging the user struct with the private keys before saving in the datastore under getUUID("struct",
username) . The last step is to store the salt under getUUID("salt", username) .


