package tw.edu.nccu.ptbre;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import tw.edu.nccu.ptbre.PTBREEngine.CFrag;
import tw.edu.nccu.ptbre.PTBREEngine.KFrag;
import tw.edu.nccu.ptbre.PTBREEngine.PTBRECipher;
import tw.edu.nccu.ptbre.PTBREEngine.PTBREKeyPair;
import tw.edu.nccu.ptbre.PTBREEngine.PTBREPrivateKey;
import tw.edu.nccu.ptbre.PTBREEngine.PTBREPublicKey;


public class PTBREPerformanceTest {
	
	static String TEST_PAIRING_PARAMETERS_PATH_a_80_256 = "params/a_80_256.properties";
	static String cipher = "AES/CBC/PKCS5Padding";
	public final static String perfomanceLogFormat = "%s\t%s";
    
	@Test
	public void test() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
//		String content = "this is our message";
		String content = "GANmMYFfG89muwQzZlm8w4Iw5sHoL2tqPUprONSOeJx3K6Eb2sCkLk4hP7LhZ7ab7nB7WQIqbDO0L95dKqVO8MxDU1PPJ0e7I6cY";
		
		List<PTBREMetric> metrics = new ArrayList();
		
		metrics.add(testPerformance(1, 20, 10, content));
		metrics.add(testPerformance(10, 20, 10, content));		
		metrics.add(testPerformance(50, 20, 10, content));		
		metrics.add(testPerformance(100, 20, 10, content));	
		metrics.add(testPerformance(200, 20, 10, content));		
		metrics.add(testPerformance(300, 20, 10, content));		
		metrics.add(testPerformance(500, 20, 10, content));
		
		System.out.println(String.format("%s\t%s\t%s\t%s\t%s\t%s\t%s", 
				"max_user", "GenKey", "encrypt", "decrypt1",
				"GenRk", "reEnc", "decrypt2"));
		
		for(PTBREMetric m: metrics) {
			System.out.println(String.format("%s\t%s\t%s\t%s\t%s\t%s\t%s", 
									m.max_user, m.GenKey, m.encrypt, m.decrypt1,
									m.GenRk, m.reEnc, m.decrypt2));
		}
	}
	

//	@Test
	static public PTBREMetric testPerformance(int max_user, int N, int K, String content) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		PTBREMetric metric = new PTBREMetric();
		
//		int max_user = 10;
//		int N = 20;
//		int K = 10;
		
		System.out.println("max_user:"+max_user);
		metric.max_user = max_user;
		
		// 1. init
		Instant start = getStartTime();
		
		int[] S = new int[] {1};
		int[] newS = new int[max_user];
		for(int i = 0;i<max_user; i++) {
			newS[i] = i+1;
		}
		
		IvParameterSpec ivParam = FileEncrypterDecrypter.generateRandomIv();
		PTBREEngine engine = new PTBREEngine(TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		
		// printEndTimeAndElapsed("Init", start);
		
		// 2. create key
		// symmetric key
		start = getStartTime();
		
		SecretKey symmetricKey = FileEncrypterDecrypter.generateSecreteKey();
		FileEncrypterDecrypter encryptor = new FileEncrypterDecrypter(symmetricKey, cipher);
		
		// broadcast key
		start = getStartTime();
		
		PTBREKeyPair keyPair = engine.setup(max_user);
        PTBREPublicKey pk = keyPair.publicKey();
        int alice_idx = 1;
        PTBREPrivateKey sk_a = engine.keyGen(keyPair, alice_idx);
        PTBREPrivateKey[] delegatees = new PTBREPrivateKey[max_user];
        for(int i = 0;i<max_user; i++) {
        	delegatees[i] = engine.keyGen(keyPair, i+1);
		}
		
        metric.GenKey = printEndTimeAndElapsed("GenKey", start);
        
        
        
	    // 3. encrypt
        start = getStartTime();
        // encrypt by symmetric key
		String ciphertext = encryptor.encrypt(content, ivParam);
		
		// encrypt by PTBRE
		byte[] keyByes = Base64.getEncoder().encodeToString(symmetricKey.getEncoded()).getBytes();
		PTBRECipher C = engine.encrypt(pk, S, keyByes);
		
		metric.encrypt = printEndTimeAndElapsed("encrypt", start);
		
        
        // 4.decrypt1
		start = getStartTime();
		// decrypt by PTBRE
		String symmetricKeyStr = Util.bytesToString(engine.decrypt_1(pk, sk_a, alice_idx, S, C));
		
		// decrypt by symmetric key
		byte[] symmetricKeyByes = Base64.getDecoder().decode(symmetricKeyStr);
		SecretKey origSymmetricKey = new SecretKeySpec(symmetricKeyByes, 0, symmetricKeyByes.length, "AES"); 
		FileEncrypterDecrypter decryptor = new FileEncrypterDecrypter(origSymmetricKey, cipher);
		String recoverContent = decryptor.decrypt(ciphertext, ivParam);
		
//		System.out.println(recoverContent);
//		Assert.assertEquals(content, recoverContent);
		metric.decrypt1 = printEndTimeAndElapsed("decrypt1", start);
		
		
		// 5. GenRk
		start = getStartTime();
		KFrag[] kFrags = engine.rkGen(pk, sk_a, alice_idx, newS, N, K);
		metric.GenRk = printEndTimeAndElapsed("GenRk", start);
		
		
		// 6. ReEncrypt
		start = getStartTime();
		CFrag[] cFrags = new CFrag[kFrags.length];
		for(int i=0; i< kFrags.length; i++)
			cFrags[i] = engine.reEnc(pk, kFrags[i], alice_idx, S, newS, C);
		
		metric.reEnc = printEndTimeAndElapsed("reEnc", start);
		
		
		// 6. Decrypt
		start = getStartTime();
		CFrag[] cFragsForDecrypt = new CFrag[K];
		for(int i = 0;i<K;i++) {
			cFragsForDecrypt[i] = cFrags[i];
		}
		
		for(int i = 0;i<max_user; i++) {
			String symmetricKeyStrFromDc2 = 
					Util.bytesToString(engine.decrypt_2(pk, delegatees[i], alice_idx, i+1, S, newS, cFragsForDecrypt));
			
			byte[] symmetricKeyByesFromDc2 = Base64.getDecoder().decode(symmetricKeyStrFromDc2);
			SecretKey origSymmetricKeyFromDc2 = new SecretKeySpec(symmetricKeyByesFromDc2, 0, symmetricKeyByesFromDc2.length, "AES"); 
			FileEncrypterDecrypter decryptor2 = new FileEncrypterDecrypter(origSymmetricKeyFromDc2, cipher);
			String recoverContentFromDc2 = decryptor2.decrypt(ciphertext, ivParam);
			
//			System.out.println(recoverContentFromDc2);
		}
		metric.decrypt2 = printEndTimeAndElapsed("decrypt2", start);
		
		System.out.println("");
		
		return metric;
	}
	

	static private long printEndTimeAndElapsed(String function, Instant start) {
		Instant end = Instant.now();
		long timpElaped = Duration.between(start, end).toMillis();
		System.out.println(String.format(perfomanceLogFormat, function,  timpElaped));
		
		return timpElaped;
	}


	static private Instant getStartTime() {
		Instant start = Instant.now();
//		System.out.println(start);
		return start;
	}
	
	public static class PTBREMetric{
		int max_user = 0;
		long GenKey = 0;
		long encrypt = 0;
		long decrypt1 = 0;
		long GenRk = 0;
		long reEnc = 0;
		long decrypt2 = 0;
	}

}
