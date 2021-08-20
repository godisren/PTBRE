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

import org.apache.commons.cli.ParseException;

import tw.edu.nccu.ptbre.PTBREEngine.CFrag;
import tw.edu.nccu.ptbre.PTBREEngine.KFrag;
import tw.edu.nccu.ptbre.PTBREEngine.PTBRECipher;
import tw.edu.nccu.ptbre.PTBREEngine.PTBREKeyPair;
import tw.edu.nccu.ptbre.PTBREEngine.PTBREPrivateKey;
import tw.edu.nccu.ptbre.PTBREEngine.PTBREPublicKey;

public class PerformanceMain {
	
	public static String TEST_PAIRING_PARAMETERS_PATH_a_80_256 = "params/a_80_256.properties";
	public static String cipher = "AES/CBC/PKCS5Padding";
	public final static String perfomanceLogFormat = "%s\t%s";

	public static void main(String[] args) throws Exception {
		String content = "GANmMYFfG89muwQzZlm8w4Iw5sHoL2tqPUprONSOeJx3K6Eb2sCkLk4hP7LhZ7ab7nB7WQIqbDO0L95dKqVO8MxDU1PPJ0e7I6cY";
		
		List<PTBREMetric> metrics = new ArrayList();
		int batchSizePerRun = 5;
		
		
		// case 0
		metrics.add(batchExecute(2, 10, 10, 5, content));
		metrics.add(batchExecute(20, 10, 5, 3, content));
		
		
		// case 1
//		metrics.add(batchExecute(batchSizePerRun, 10, 55, 10, content));
//		metrics.add(batchExecute(batchSizePerRun, 10, 50, 10, content));
//		metrics.add(batchExecute(batchSizePerRun, 10, 45, 10, content));
//		metrics.add(batchExecute(batchSizePerRun, 10, 40, 10, content));
//		metrics.add(batchExecute(batchSizePerRun, 10, 35, 10, content));
//		metrics.add(batchExecute(batchSizePerRun, 10, 30, 10, content));
//		metrics.add(batchExecute(batchSizePerRun, 10, 25, 10, content));
//		metrics.add(batchExecute(batchSizePerRun, 10, 20, 10, content));
//		metrics.add(batchExecute(batchSizePerRun, 10, 15, 10, content));
		
		
		// case 2
//		metrics.add(batchExecute(batchSizePerRun, 10, 50, 48, content));
//		metrics.add(batchExecute(batchSizePerRun, 10, 50, 45, content));
//		metrics.add(batchExecute(batchSizePerRun, 10, 50, 40, content));
//		metrics.add(batchExecute(batchSizePerRun, 10, 50, 35, content));
//		metrics.add(batchExecute(batchSizePerRun, 10, 50, 30, content));
//		metrics.add(batchExecute(batchSizePerRun, 10, 50, 25, content));
//		metrics.add(batchExecute(batchSizePerRun, 10, 50, 20, content));
//		metrics.add(batchExecute(batchSizePerRun, 10, 50, 15, content));
//		metrics.add(batchExecute(batchSizePerRun, 10, 50, 10, content));
		
		
		System.out.println(String.format("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s", 
				"max_user", "N", "K", "GenKey", "encrypt", "decrypt1",
				"GenRk", "reEnc", "decrypt2"));
		
		for(PTBREMetric m: metrics) {
			System.out.println(String.format("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s", 
									m.max_user, m.N, m.K, m.GenKey, m.encrypt, m.decrypt1,
									m.GenRk, m.reEnc, m.decrypt2));
		}
	}
	
	static public PTBREMetric batchExecute(int batchSize, int max_user, int N, int K, String content) throws Exception {
		
		PTBREMetric avgMetric = new PTBREMetric();
		for(int i = 0;i<batchSize;i++) {
			PTBREMetric m = testPerformance(max_user, N, K, content);
			avgMetric.GenKey += m.GenKey;
			avgMetric.encrypt += m.encrypt;
			avgMetric.decrypt1 += m.decrypt1;
			avgMetric.GenRk += m.GenRk;
			avgMetric.reEnc += m.reEnc;
			avgMetric.decrypt2 += m.decrypt2;
		}
		
		System.out.println("average on batch size="+batchSize);
		avgMetric.max_user = max_user;
		avgMetric.N = N;
		avgMetric.K = K;
		avgMetric.GenKey = avgMetric.GenKey / batchSize;
		avgMetric.encrypt = avgMetric.encrypt / batchSize;
		avgMetric.decrypt1 = avgMetric.decrypt1 / batchSize;
		avgMetric.GenRk = avgMetric.GenRk / batchSize;
		avgMetric.reEnc = avgMetric.reEnc / batchSize;
		avgMetric.decrypt2 = avgMetric.decrypt2 / batchSize;
		
		return avgMetric;
		
	}
	
	static public PTBREMetric testPerformance(int max_user, int N, int K, String content) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		PTBREMetric metric = new PTBREMetric();
		
//		int max_user = 10;
//		int N = 20;
//		int K = 10;
		
		System.out.println("max_user:"+max_user);
		metric.max_user = max_user;
		metric.N = N;
		metric.K = K;
		
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
		CFrag[] cFrags = new CFrag[K];
		for(int i=0; i< K; i++)
			cFrags[i] = engine.reEnc(pk, kFrags[i], alice_idx, S, newS, C);
		
		metric.reEnc = printEndTimeAndElapsed("reEnc", start);
		
		
		// 6. Decrypt
		for(int i = 0;i<max_user; i++) {
			start = getStartTime();
			CFrag[] cFragsForDecrypt = new CFrag[K];
			for(int j = 0;j<K;j++) {
				cFragsForDecrypt[j] = cFrags[j];
			}
			
			
			String symmetricKeyStrFromDc2 = 
					Util.bytesToString(engine.decrypt_2(pk, delegatees[i], alice_idx, i+1, S, newS, cFragsForDecrypt));
			
			byte[] symmetricKeyByesFromDc2 = Base64.getDecoder().decode(symmetricKeyStrFromDc2);
			SecretKey origSymmetricKeyFromDc2 = new SecretKeySpec(symmetricKeyByesFromDc2, 0, symmetricKeyByesFromDc2.length, "AES"); 
			FileEncrypterDecrypter decryptor2 = new FileEncrypterDecrypter(origSymmetricKeyFromDc2, cipher);
			String recoverContentFromDc2 = decryptor2.decrypt(ciphertext, ivParam);
			
//			System.out.println(recoverContentFromDc2);
		}
		// average per user
		metric.decrypt2 = printEndTimeAndElapsed("decrypt2", start) / max_user;
		
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
		int N = 0;
		int K = 0;
		long GenKey = 0;
		long encrypt = 0;
		long decrypt1 = 0;
		long GenRk = 0;
		long reEnc = 0;
		long decrypt2 = 0;
	}
		
}
