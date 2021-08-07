install depend external libs

```sh
mvn install:install-file -Dfile=jpbc-api-2.0.0.jar -DgroupId=it.unisa.dia.gas.jpbc -DartifactId=jpbc-api -Dversion=2.0.0 -Dpackaging=jar

mvn install:install-file -Dfile=jpbc-crypto-2.0.0.jar -DgroupId=it.unisa.dia.gas.jpbc -DartifactId=jpbc-crypto -Dversion=2.0.0 -Dpackaging=jar

mvn install:install-file -Dfile=jpbc-plaf-2.0.0.jar -DgroupId=it.unisa.dia.gas.jpbc -DartifactId=jpbc-plaf -Dversion=2.0.0 -Dpackaging=jar
```

build executable jar

```sh
mvn compile assembly:single
```


```sh
$ java nccu-ptbre.jar setup -n 10
The maximum number of users：10
Generate broadcast public key：broadcast.pk
Generate master secret key：broadcast.msk
 
$ java nccu-ptbre.jar genKey msk_file=broadcast.msk idx=1,2,5
Generate private key(idx=1,2,5)：
1.sk
2.sk
5.sk

$ java nccu-ptbre.jar encrypt pk=be.pk recipient_idx_set=1 m=This_is_my_key
Encrypt by public key and recipient index(idx=1)：
ciphertext.cipher

$ java nccu-ptbre.jar decrypt sk_idx=1 sk=1.sk cipher_file=ciphertext.cipher
Decrypt by private key and recipient index(idx=1), output the plaintext:$
This_is_my_key

$ java nccu-ptbre.jar genRK pk=be.pk owner_idx_set=1 owner_idx=1 owner_sk=1.sk recipient_idx_set==2,3 N=5 t=3
Generate re-encryption key share (kFrag), owner index set (idx=1) to recipient index set (idx=2,3):
1.kfrag
2.kfrag
3.kfrag
4.kfrag
5.kfrag

$ java nccu-ptbre.jar reencrypt pk=be.pk owner_idx_set=1 owner_idx=1 recipient_idx_set=3,4 kfrag_file=1.kfrag ciphertext=cipyher.txt 
Generate re-encryption ciphertext  share(cFrag) ：
1.cfrag

$ java nccu-ptbre.jar reencrypt pk=be.pk owner_idx_set=1 owner_idx=1 recipient_idx_set=3,4 kfrag_file=2.kfrag ciphertext=cipyher.txt 
Generate re-encryption ciphertext  share(cFrag) ：
2.cfrag

$ java nccu-ptbre.jar reencrypt pk=be.pk owner_idx_set=1 owner_idx=1 recipient_idx_set=3,4 kfrag_file=3.kfrag ciphertext=cipyher.txt 
Generate re-encryption ciphertext  share(cFrag) ：
3.cfrag

java nccu-ptbre.jar redecrypt pk=be.pk owner_idx_set=1 owner_idx=1 recipient_idx_set==3,4 recipient_sk=2.sk cfrag_files=1.cfrag,3.cfrag,5.cfrag
Re-Decrypt by recipeint private key：
This_is_my_key
```





```sh

$ java nccu-ptbre.jar encrypt pk=be.pk recipient_idx_set=1 -f test.txt
Encrypt by public key and recipient index(idx=1)：
test.en
test.capsulation

$ java nccu-ptbre.jar decrypt sk_idx=1 sk=1.sk encrypted_file=ciphertext.enc capsulation_file=test.capsulation output_file=test_recovery.txt
Decrypt by private key and recipient index(idx=1), output the plaintext:
test_recovery.txt

$ java nccu-ptbre.jar genRK pk=be.pk owner_idx=1 owner_sk=1.sk recipient_idx_set=2,3 N=5 K=3
Generate re-encryption key share (kFrag), owner index set (idx=1) to recipient index set (idx=2,3):
1.kfrag
2.kfrag
3.kfrag
4.kfrag
5.kfrag

$ java nccu-ptbre.jar reEncrypt pk=be.pk owner_idx_set=1 owner_idx=1 recipient_idx_set=2,3 kfrag_file=1.kfrag capsulation_file=test.capsulation 
Generate re-encryption ciphertext  share(cFrag) ：
1.cfrag

java nccu-ptbre.jar decrypt2 pk=broadcast.pk owner_idx_set=1 owner_idx=1 recipient_idx_set=2,3 recipient_idx=2 sk=2.sk cfrag_files=1.cfrag,3.cfrga,5.cgrag encrypted_file=test.enc output_file=test_recovery2.txt
Re-Decrypt by recipeint private key：
This_is_my_key
```