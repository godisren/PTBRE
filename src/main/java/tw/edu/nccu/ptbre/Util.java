package tw.edu.nccu.ptbre;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.crypto.CipherParameters;

import tw.edu.nccu.ptbre.PTBREEngine.PTBREPublicKey;

public class Util {
	
	public static void writeFile(File file, CipherParameters param) throws IOException {
		byte[] bytes = Util.SerCipherParameter(param);
        FileUtils.writeByteArrayToFile(file, bytes);
	}
	
	public static CipherParameters readCipherFile(File file) throws IOException, ClassNotFoundException {
		byte[] bytes = FileUtils.readFileToByteArray(file);
        return Util.deserCipherParameters(bytes);
	}
	
	public static byte[] SerCipherParameter(CipherParameters cipherParameters) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(cipherParameters);
        byte[] byteArray = byteArrayOutputStream.toByteArray();
        objectOutputStream.close();
        byteArrayOutputStream.close();
        return byteArray;
    }

    public static CipherParameters deserCipherParameters(byte[] byteArrays) throws IOException, ClassNotFoundException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrays);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        CipherParameters cipherParameters = (CipherParameters)objectInputStream.readObject();
        objectInputStream.close();
        byteArrayInputStream.close();
        return cipherParameters;
    }
    
    public static String bytesToString(byte[] bytes) {
    	return new String(bytes, StandardCharsets.UTF_8);
    }

	public static byte[] getBytesFromSecretKey(SecretKey secretKey) {
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
		
		return encodedKey.getBytes();
	}
	
	public static byte[] getBytesFromDecodeKey(String decodedKeyStr) {
		byte[] decodedKey = Base64.getDecoder().decode(decodedKeyStr);
		return decodedKey;
	}

	public static SecretKey recoverSecretKeyFromDecodeKey(byte[] decodedKey) {

	    String decordeKeyStr = Util.bytesToString(decodedKey);
		// decode the base64 encoded string
		decodedKey = Base64.getDecoder().decode(decordeKeyStr);
		
		SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"); 
		return originalKey;
	}
}
