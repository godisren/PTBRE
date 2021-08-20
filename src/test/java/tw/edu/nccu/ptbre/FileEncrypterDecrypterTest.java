package tw.edu.nccu.ptbre;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Test;

import tw.edu.nccu.ptbre.PTBREEngine.PTBRECipher;
import tw.edu.nccu.ptbre.PTBREEngine.PTBREKeyPair;
import tw.edu.nccu.ptbre.PTBREEngine.PTBREPrivateKey;
import tw.edu.nccu.ptbre.PTBREEngine.PTBREPublicKey;


public class FileEncrypterDecrypterTest {

	@Test
	public void test() throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeyException, InvalidAlgorithmParameterException {

		SecretKey secretKey = FileEncrypterDecrypter.generateSecreteKey();//KeyGenerator.getInstance("AES").generateKey();
		
		// test symmetric key recover
		byte[] skBytes = secretKey.getEncoded();
		SecretKey recoverSecretKey = new SecretKeySpec(skBytes, 0, skBytes.length, "AES");
		Assert.assertArrayEquals(skBytes, recoverSecretKey.getEncoded());
		
		String cipher = "AES/CBC/PKCS5Padding";
		FileEncrypterDecrypter encryptor = new FileEncrypterDecrypter(secretKey, cipher);
		
		Path path = Paths.get("./output/test.txt");
		String content = new String(Files.readAllBytes(path));
	    String fileName = "./output/test.enc";
		
	    // encrypt
		encryptor.encryptToFile(content, fileName);
		
		// integrate with PTBRE
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
		byte[] recoverSkBytes = integrateWithPTBRE(encodedKey.getBytes());
		String decordeKeyStr = Util.bytesToString(recoverSkBytes);
		// decode the base64 encoded string
		byte[] decodedKey = Base64.getDecoder().decode(decordeKeyStr);
		Assert.assertArrayEquals(skBytes, decodedKey);
		SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"); 
		FileEncrypterDecrypter decryptor = new FileEncrypterDecrypter(originalKey, cipher);
	
		
		// decrypt
		String recoverContent = decryptor.decryptToFile(fileName);
		
		Assert.assertEquals(content, recoverContent);
		
		Files.write(Paths.get("./output/output.txt"), recoverContent.getBytes());
	}
	
	
	public byte[] integrateWithPTBRE(byte[] key) {
		
		String TEST_PAIRING_PARAMETERS_PATH_a_80_256 = "params/a_80_256.properties";
	    
		
		PTBREEngine engine = new PTBREEngine(TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		
//		int dataOwnerIdx = index1_valid;
		int[] indexSet = new int[] {1};// indexSet2;
		int n = 10;

		// 1.setup
        PTBREKeyPair keyPair = engine.setup(n);
        PTBREPublicKey pk = keyPair.publicKey();
       
        // 2.genkey
        int alice_idx = 1;
        PTBREPrivateKey sk_a = engine.keyGen(keyPair, alice_idx);
        
        
        // 3.encrypt(PK, S, m)
        PTBRECipher C = engine.encrypt(pk, indexSet, key);
        
        // 4.decrypt-II
        byte[] recoverKey = engine.decrypt_1(pk, sk_a, alice_idx, indexSet, C);
        
        Assert.assertArrayEquals(key, recoverKey);
        
        return recoverKey;
	}

}
