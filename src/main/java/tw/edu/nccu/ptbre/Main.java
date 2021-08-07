package tw.edu.nccu.ptbre;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.commons.cli.ParseException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

import tw.edu.nccu.ptbre.PTBREEngine.CFrag;
import tw.edu.nccu.ptbre.PTBREEngine.KFrag;
import tw.edu.nccu.ptbre.PTBREEngine.PTBRECipher;
import tw.edu.nccu.ptbre.PTBREEngine.PTBREKeyPair;
import tw.edu.nccu.ptbre.PTBREEngine.PTBREMasterPrivateKey;
import tw.edu.nccu.ptbre.PTBREEngine.PTBREPrivateKey;
import tw.edu.nccu.ptbre.PTBREEngine.PTBREPublicKey;

public class Main {
	
	public static final String PAIRING_PARAMETERS_PATH_a_80_256 = "params/a_80_256.properties";
	public static final String cipher = "AES/CBC/PKCS5Padding";
	public static final String workingDir = "./output/";
//	public static final String workingDir = "./";
	
	
	public static void main(String[] args) throws ParseException, IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
//		System.out.println("NCCU - Proxy Threshold Broadcast Re-Encryption");
		
		Map<String, String> argMap = new LinkedHashMap();
		String operation = args[0];
		for(int i = 1;i<args.length;i++) {
			
			String[] argPair = args[i].split("=");
			
			argMap.put(argPair[0], argPair[1]);
		}
		
//		System.out.println(operation +" with parameter " + argMap);
		
		PTBREEngine engine = new PTBREEngine(PAIRING_PARAMETERS_PATH_a_80_256);
		
		if("setup".equals(operation)) {
			Integer n = Integer.valueOf(argMap.get("n"));
			
			// 1.setup
	        PTBREKeyPair keyPair = engine.setup(n);
	        
	        String pkPath = workingDir+"broadcast.pk";
	        String mskPath = workingDir+"broadcast.msk";
	        Util.writeFile(new File(pkPath), keyPair.publicKey());
	        Util.writeFile(new File(mskPath), keyPair.masterPrivateKey());
	        
	        System.out.println("[output] "+pkPath);
	        System.out.println("[output] "+mskPath);
		
		}else if("genKey".equals(operation)) {
			
			String pkFile = argMap.get("pk");
			String mskFile = argMap.get("msk_file");
			Integer idx = getInt(argMap.get("idx"));
			
			PTBREKeyPair keyPair = new PTBREKeyPair((PTBREPublicKey) Util.readCipherFile(new File(workingDir+pkFile))
					,  (PTBREMasterPrivateKey) Util.readCipherFile(new File(workingDir+mskFile)));
			
			// 2.genkey
			String skPath = workingDir+idx+".sk";
	        PTBREPrivateKey sk_a = engine.keyGen(keyPair, idx);
	        Util.writeFile(new File(skPath), sk_a);
	        
	        System.out.println("[output] "+skPath);
			
		}else if("encrypt".equals(operation)) {
			
			String pkFile = argMap.get("pk");
			int[] rece_idx_set = getIndexArray(argMap.get("recipient_idx_set"));
			String f = argMap.get("f");
			
			PTBREPublicKey pk = (PTBREPublicKey) Util.readCipherFile(new File(workingDir+pkFile));
			
		    // encrypt content with symmetric key
			
			String plaintextPath = workingDir+f;
			String content = FileUtils.readFileToString(new File(plaintextPath), Charset.forName("UTF-8"));
//			Path plaintextPath = Paths.get(workingDir+f);
//		    String content = Files.readAllLines(plaintextPath).get(0);
		    SecretKey secretKey = FileEncrypterDecrypter.generateSecreteKey();
		    FileEncrypterDecrypter encryptor = new FileEncrypterDecrypter(secretKey, cipher);
		    
		    String baseFileName = FilenameUtils.removeExtension(FilenameUtils.getBaseName(plaintextPath));
		    String encryptedPath = workingDir+baseFileName+".enc";
		    encryptor.encryptToFile(content, encryptedPath);
		    
			// 3.encapsulate(PK, S, m)
	        String capsulationPath = workingDir+baseFileName+".capsulation";
		    PTBRECipher C = engine.encrypt(pk, rece_idx_set, Util.getBytesFromSecretKey(secretKey));
	        Util.writeFile(new File(capsulationPath), C);
	        
	        System.out.println("[output] "+encryptedPath);
	        System.out.println("[output] "+capsulationPath);
	        
		}else if("decrypt".equals(operation)) {
			
			String pkFile = argMap.get("pk");
			String skFile = argMap.get("sk");
			Integer sk_idx = getInt(argMap.get("sk_idx"));
			int[] rece_idx_set = getIndexArray(argMap.get("recipient_idx_set"));
			String encryptedFile  = argMap.get("encrypted_file");
			String capsulationFile = argMap.get("capsulation_file");
			String outputFile = argMap.get("output_file");
			
			PTBREPublicKey pk = (PTBREPublicKey) Util.readCipherFile(new File(workingDir+pkFile));
			PTBREPrivateKey sk_a = (PTBREPrivateKey) Util.readCipherFile(new File(workingDir+skFile));
			PTBRECipher C = (PTBRECipher) Util.readCipherFile(new File(workingDir+capsulationFile));
			
			// decrypt KEM first
		    byte[] recover_key_bytes = engine.decrypt_1(pk, sk_a, sk_idx, rece_idx_set, C);
	     
		    SecretKey secretKey = Util.recoverSecretKeyFromDecodeKey(recover_key_bytes);
		    FileEncrypterDecrypter decryptor = new FileEncrypterDecrypter(secretKey, cipher);
		    String recoverContent = decryptor.decryptToFile(workingDir+encryptedFile);
		    
		    String resultPath = workingDir+outputFile;
		    Files.write(Paths.get(resultPath), recoverContent.getBytes());
		    
		    System.out.println("[output] "+resultPath);
		}else if("genRK".equals(operation)) {
			
			String pkFile = argMap.get("pk");
			String skFile = argMap.get("owner_sk");
			int owner_idx = getInt(argMap.get("owner_idx"));
			int[] rece_idx_set = getIndexArray(argMap.get("recipient_idx_set"));
			int N = getInt(argMap.get("N"));
			int K = getInt(argMap.get("K"));
			
			PTBREPublicKey pk = (PTBREPublicKey) Util.readCipherFile(new File(workingDir+pkFile));
			PTBREPrivateKey sk_a = (PTBREPrivateKey) Util.readCipherFile(new File(workingDir+skFile));
			
			KFrag[] kFrags = engine.rkGen(pk, sk_a, owner_idx, rece_idx_set, N, K);
			for(int i = 0;i<kFrags.length;i++) {
	        	KFrag kFrag = kFrags[i];
	        	
	        	String filePath = workingDir+ (i+1) + ".kfrag";
	        	Util.writeFile(new File(filePath), kFrag);
	        	
	        	System.out.println("[output] " + filePath);
	        }
			
		}else if("reEncrypt".equals(operation)) {
			
			String pkFile = argMap.get("pk");
			int owner_idx = getInt(argMap.get("owner_idx"));
			int[] owner_idx_set = getIndexArray(argMap.get("owner_idx_set"));
			int[] rece_idx_set = getIndexArray(argMap.get("recipient_idx_set"));
			String kfragFile = argMap.get("kfrag_file");
			String capsulationFile = argMap.get("capsulation_file");
			
			PTBREPublicKey pk = (PTBREPublicKey) Util.readCipherFile(new File(workingDir+pkFile));
			KFrag kFrag = (KFrag) Util.readCipherFile(new File(workingDir+kfragFile));
			PTBRECipher C = (PTBRECipher) Util.readCipherFile(new File(workingDir+capsulationFile));
			
			
			CFrag cfrag = engine.reEnc(pk, kFrag, owner_idx, owner_idx_set, rece_idx_set, C);
			String baseFileName = FilenameUtils.removeExtension(FilenameUtils.getBaseName(kfragFile));
		    String filePath = workingDir+ baseFileName + ".cfrag";
        	Util.writeFile(new File(filePath), cfrag);
        	
        	System.out.println("[output] " + filePath);
        	
		}else if("decrypt2".equals(operation)) {
			
			String pkFile = argMap.get("pk");
			String skFile = argMap.get("sk");
			Integer owner_idx = getInt(argMap.get("owner_idx"));
			int[] owner_idx_set = getIndexArray(argMap.get("owner_idx_set"));
			Integer recipient_idx = getInt(argMap.get("recipient_idx"));
			int[] rece_idx_set = getIndexArray(argMap.get("recipient_idx_set"));
			String encryptedFile  = argMap.get("encrypted_file");
			CFrag[] cFrags = getCfrag(argMap.get("cfrag_files"));
			String outputFile = argMap.get("output_file");
			
			PTBREPublicKey pk = (PTBREPublicKey) Util.readCipherFile(new File(workingDir+pkFile));
			PTBREPrivateKey sk = (PTBREPrivateKey) Util.readCipherFile(new File(workingDir+skFile));
			
			// decrypt KEM first
			byte[] recover_key_bytes = engine.decrypt_2(pk, sk, owner_idx, recipient_idx, owner_idx_set, rece_idx_set, cFrags);
	        
		    SecretKey secretKey = Util.recoverSecretKeyFromDecodeKey(recover_key_bytes);
		    FileEncrypterDecrypter decryptor = new FileEncrypterDecrypter(secretKey, cipher);
		    String recoverContent = decryptor.decryptToFile(workingDir+encryptedFile);
		    
		    String plaintextPath = workingDir+outputFile;
		    Files.write(Paths.get(plaintextPath), recoverContent.getBytes());
		    

	        System.out.println("[output] " + plaintextPath);
		}else if("encapsulate".equals(operation)) {
			
			String pkFile = argMap.get("pk");
			int[] rece_idx_set = getIndexArray(argMap.get("recipient_idx_set"));
			String m = argMap.get("m");
			
			PTBREPublicKey pk = (PTBREPublicKey) Util.readCipherFile(new File(workingDir+pkFile));
			
			// 3.encapsulate(PK, S, m)
	        PTBRECipher C = engine.encrypt(pk, rece_idx_set, m.getBytes());
	        Util.writeFile(new File(workingDir+"ciphertext.cipher"), C);
	        
		}else if("decapsulate".equals(operation)) {
			
			String pkFile = argMap.get("pk");
			String skFile = argMap.get("sk");
			String cipher_file = argMap.get("cipher_file");
			Integer sk_idx = getInt(argMap.get("sk_idx"));
			int[] rece_idx_set = getIndexArray(argMap.get("recipient_idx_set"));
			
			PTBREPublicKey pk = (PTBREPublicKey) Util.readCipherFile(new File(workingDir+pkFile));
			PTBREPrivateKey sk_a = (PTBREPrivateKey) Util.readCipherFile(new File(workingDir+skFile));
			PTBRECipher C = (PTBRECipher) Util.readCipherFile(new File(workingDir+cipher_file));
			
	        byte[] recover_m_bytes = engine.decrypt_1(pk, sk_a, sk_idx, rece_idx_set, C);
	        
	        String recover_m =  new String(recover_m_bytes, StandardCharsets.UTF_8);
//	        
	        System.out.println("decrypt:"+recover_m);
		}
	
	}

	private static Integer getInt(String val) {
		return Integer.valueOf(val);
	}

	private static int[] getIndexArray(String val) {
		String[] vals = val.split(",");
		int[] intVals = new int[vals.length];
		for(int i = 0;i<vals.length;i++) {
			intVals[i] = Integer.valueOf(vals[i]);
		}
		return intVals;
	}
	
	private static CFrag[] getCfrag(String val) throws ClassNotFoundException, IOException {
		String[] vals = val.split(",");
		CFrag[] cFrags = new CFrag[vals.length];
		for(int i = 0;i<vals.length;i++) {
			cFrags[i] = (CFrag) Util.readCipherFile(new File(workingDir+vals[i]));
			
		}
		return cFrags;
	}

}
