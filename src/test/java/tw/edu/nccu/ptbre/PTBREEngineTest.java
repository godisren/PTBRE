package tw.edu.nccu.ptbre;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.FileUtils;
import org.junit.Assert;
import org.junit.Test;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import tw.edu.nccu.ptbre.PTBREEngine;
import tw.edu.nccu.ptbre.Util;
import tw.edu.nccu.ptbre.PTBREEngine.CFrag;
import tw.edu.nccu.ptbre.PTBREEngine.KFrag;
import tw.edu.nccu.ptbre.PTBREEngine.PTBRECipher;
import tw.edu.nccu.ptbre.PTBREEngine.PTBREKeyPair;
import tw.edu.nccu.ptbre.PTBREEngine.PTBREMasterPrivateKey;
import tw.edu.nccu.ptbre.PTBREEngine.PTBREPrivateKey;
import tw.edu.nccu.ptbre.PTBREEngine.PTBREPublicKey;

public class PTBREEngineTest {
	
	public static final String TEST_PAIRING_PARAMETERS_PATH_a_80_256 = "params/a_80_256.properties";
    public static final String TEST_PAIRING_PARAMETERS_PATH_a1_2_128 = "params/a1_2_128.properties";
    public static final String TEST_PAIRING_PARAMETERS_PATH_a1_3_128 = "params/a1_3_128.properties";
	
	@Test
	public void testEngine() {
		
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
//        PTBREPrivateKey sk_c = engine.keyGen(keyPair, 5);
  
        // 3.encrypt(PK, S, m)
        String m = "this is secret";
        PTBRECipher C = engine.encrypt(pk, indexSet, m.getBytes());
        
        // 4.decrypt-II
        
        byte[] recover_m_bytes = engine.decrypt_1(pk, sk_a, alice_idx, indexSet, C);
        
        String recover_m = new String(recover_m_bytes, StandardCharsets.UTF_8);
        
        System.out.println("decrypt:"+recover_m);
        Assert.assertArrayEquals(m.getBytes(), recover_m_bytes );
        
        
        // ============================================================================================================================

        // Re-Encryption (prepare)
                
        // 5. RKGen()
        int[] indexSetOfNewSet = new int[]{4,5,6,7};
        int bob_idx = 7;
        int N = 5, t=3;
        PTBREPrivateKey sk_b = engine.keyGen(keyPair, bob_idx);
        
        
        KFrag[] kFrags = engine.rkGen(pk, sk_a, alice_idx, indexSetOfNewSet, N, t);
        
        
        // 6. ReEnc()
        CFrag[] cFrags = new CFrag[t];
        for(int i = 0;i<t;i++) {
        	
        	CFrag C_re = engine.reEnc(pk, kFrags[i], alice_idx, indexSet, indexSetOfNewSet, C);
        	cFrags[i] = C_re;
        }
        
        // 7.decrypt-I
        byte[] recover_m_by_bob = engine.decrypt_2(pk, sk_b, alice_idx, bob_idx, indexSet, indexSetOfNewSet, cFrags);
        
        System.out.println("decrypt by delegatee : "+new String(recover_m_by_bob, StandardCharsets.UTF_8));
		Assert.assertArrayEquals(m.getBytes(), recover_m_by_bob);
	}
	
	@Test
	public void testEngineWithFiles() throws IOException, ClassNotFoundException {
		
		String workingDir = "./output/";
		FileUtils.cleanDirectory(new File(workingDir));
		
		PTBREEngine engine = new PTBREEngine(TEST_PAIRING_PARAMETERS_PATH_a_80_256);
		
//		int dataOwnerIdx = index1_valid;
		int[] indexSet = new int[] {1};// indexSet2;
		int n = 10;

		// 1.setup
        PTBREKeyPair keyPair = engine.setup(n);
        PTBREPublicKey pk = keyPair.publicKey();
        
        // test Serializable
        Util.writeFile(new File(workingDir+"broadcast.pk"), pk);
        pk = (PTBREPublicKey) Util.readCipherFile(new File(workingDir+"broadcast.pk"));
        
        Util.writeFile(new File(workingDir+"broadcast.msk"), keyPair.masterPrivateKey());
        PTBREMasterPrivateKey msk = (PTBREMasterPrivateKey) Util.readCipherFile(new File(workingDir+"broadcast.msk"));       
        
        keyPair  = new PTBREKeyPair(pk, msk);
        
        // 2.genkey
        int alice_idx = 1;
        
//        Element sk_a = engine.keyGen(keyPair, alice_idx);
        PTBREPrivateKey sk_a = engine.keyGen(keyPair, alice_idx);
//        PTBREPrivateKey sk_a = new PTBREPrivateKey();
        
//        Util.writeFile(new File(workingDir+"1.sk"), pk);
//        pk = (PTBREPublicKey) Util.readFile(new File(workingDir+"1.sk"));
        
        
        // 3.encrypt(PK, S, m)
        String m = "this is secret";
        PTBRECipher C = engine.encrypt(pk, indexSet, m.getBytes());
        
        // test Serializable
        Util.writeFile(new File(workingDir+"ciphertext.cipher"), C);
        PTBRECipher C2 = (PTBRECipher) Util.readCipherFile(new File(workingDir+"ciphertext.cipher"));
        
        Assert.assertTrue(PairingUtils.isEqualElement(C.C1(), C2.C1()));
        Assert.assertTrue(PairingUtils.isEqualElement(C.C2(), C2.C2()));
        Assert.assertTrue(PairingUtils.isEqualElement(C.C3(), C2.C3()));
        Assert.assertTrue(PairingUtils.isEqualElement(C.C4(), C2.C4()));
        Assert.assertArrayEquals(C.C5(), C2.C5());
        Assert.assertTrue(PairingUtils.isEqualElement(C.C6(), C2.C6()));
        C = C2;
        
        // 4.decrypt-II
        byte[] recover_m = engine.decrypt_1(pk, sk_a, alice_idx, indexSet, C);
        
        System.out.println("decrypt:"+recover_m);
        Assert.assertArrayEquals(m.getBytes(), recover_m );
        
        
        // ============================================================================================================================

        // Re-Encryption (prepare)
                
        // 5. RKGen()
        int[] indexSetOfNewSet = new int[]{4,5,6,7};
        int bob_idx = 6;
        int N = 5, t=3;
//        Element sk_b = engine.keyGen(keyPair, bob_idx);
        PTBREPrivateKey sk_b = engine.keyGen(keyPair, bob_idx);
        
        KFrag[] kFrags = engine.rkGen(pk, sk_a, alice_idx, indexSetOfNewSet, N, t);
        
        // test Serializable
        for(int i = 0;i<kFrags.length;i++) {
        	KFrag kFrag = kFrags[i];
        	
        	String filePath = workingDir+ i + ".kfrag";
        	
        	Util.writeFile(new File(filePath), kFrag);
        	KFrag kFrag_from_file = (KFrag) Util.readCipherFile(new File(filePath));
            
            Assert.assertTrue(PairingUtils.isEqualElement(kFrag.rk_id(), kFrag_from_file.rk_id()));
            Assert.assertTrue(PairingUtils.isEqualElement(kFrag.rky(), kFrag_from_file.rky()));
            Assert.assertTrue(PairingUtils.isEqualElement(kFrag.rk().rk1(), kFrag.rk().rk1()));
            Assert.assertTrue(PairingUtils.isEqualElement(kFrag.rk().rk2(), kFrag.rk().rk2()));
            Assert.assertTrue(PairingUtils.isEqualElement(kFrag.rk().rk3(), kFrag.rk().rk3()));
            Assert.assertTrue(PairingUtils.isEqualElement(kFrag.rk().rk4(), kFrag.rk().rk4()));
            Assert.assertArrayEquals(kFrag.rk().rk5(), kFrag.rk().rk5());
            Assert.assertTrue(PairingUtils.isEqualElement(kFrag.rk().rk6(), kFrag.rk().rk6()));
            Assert.assertTrue(PairingUtils.isEqualElement(kFrag.rk().rk7(), kFrag.rk().rk7()));
            
            kFrags[i] = kFrag_from_file;
        }
        
        
        // 6. ReEnc()
        CFrag[] cFrags = new CFrag[t];
        for(int i = 0;i<t;i++) {
        	CFrag C_re = engine.reEnc(pk, kFrags[i], alice_idx, indexSet, indexSetOfNewSet, C);
        	cFrags[i] = C_re;
        }
        
        for(int i = 0;i<t;i++) {
//        	CFrag cfrag = engine.reEnc(pk, kFrags[i], alice_idx, indexSet, indexSetOfNewSet, C);
        	CFrag cfrag = cFrags[i];
        	String filePath = workingDir+ i + ".cfrag";
        	
        	Util.writeFile(new File(filePath), cfrag);
        	CFrag cFrag_from_file = (CFrag) Util.readCipherFile(new File(filePath));
        	
        	cFrags[i] = cFrag_from_file;
        }
        
//        
//        // 7.decrypt-I
        byte[] recover_m_by_bob = engine.decrypt_2(pk, sk_b, alice_idx, bob_idx, indexSet, indexSetOfNewSet, cFrags);
        
        System.out.println("decrypt by delegatee : "+new String(recover_m_by_bob, StandardCharsets.UTF_8));
//		Assert.assertEquals(m, recover_m_by_bob);
	}
}
