package tw.edu.nccu.ptbre;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * TODO there is a problem, the breakline disappear
 * @author stone
 *
 */
public class FileEncrypterDecrypter {
	
	private SecretKey secretKey;
    private Cipher cipher;

    FileEncrypterDecrypter(SecretKey secretKey, String cipher) throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.secretKey = secretKey;
        this.cipher = Cipher.getInstance(cipher);
    }

    void encryptToFile(String content, String fileName) throws InvalidKeyException, IOException {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.getIV();
       

        try (
                FileOutputStream fileOut = new FileOutputStream(fileName);
                CipherOutputStream cipherOut = new CipherOutputStream(fileOut, cipher)
        ) {
            fileOut.write(iv);
            cipherOut.write(content.getBytes());
        }

    }

    String decryptToFile(String fileName) throws InvalidAlgorithmParameterException, InvalidKeyException, IOException {

        String content;

        try (FileInputStream fileIn = new FileInputStream(fileName)) {
            byte[] fileIv = new byte[16];
            fileIn.read(fileIv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(fileIv));

            try (
                    CipherInputStream cipherIn = new CipherInputStream(fileIn, cipher);
                    InputStreamReader inputReader = new InputStreamReader(cipherIn);
                    BufferedReader reader = new BufferedReader(inputReader)
                ) {
            	
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
                content = sb.toString();
            }

        }
        return content;
    }
    
    String encrypt(String content, IvParameterSpec ivParam) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParam);

        byte[] cipherText = cipher.doFinal(content.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);

    }
    
    public String decrypt(String cipherText, IvParameterSpec ivParam) throws NoSuchPaddingException, NoSuchAlgorithmException,
	    InvalidAlgorithmParameterException, InvalidKeyException,
	    BadPaddingException, IllegalBlockSizeException {
    	
    	cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParam);
    	
	    byte[] plainText = cipher.doFinal(Base64.getDecoder()
	        .decode(cipherText));
	    return new String(plainText);
	}

	public static SecretKey generateSecreteKey() throws NoSuchAlgorithmException {
		SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
		
		return secretKey;
	}

	public static IvParameterSpec generateRandomIv() {
		byte[] iv = new byte[16]; 
		SecureRandom prng = new SecureRandom();
		prng.nextBytes(iv);
		IvParameterSpec ivParam = new IvParameterSpec(iv);

		return ivParam;
	}
}
