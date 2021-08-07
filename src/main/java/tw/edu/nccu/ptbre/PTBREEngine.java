package tw.edu.nccu.ptbre;

import java.io.Serializable;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.function.BiFunction;
import java.util.function.Function;

import org.bouncycastle.crypto.CipherParameters;
import org.junit.Assert;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.utils.PairingUtils.PairingGroupType;

//import com.example.TestUtils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * A proxy threshold broadcast re-encryption
 * refactor 2 (rk7), this is okay version
 * 
 * @author stone
 *
 */
public class PTBREEngine {
    
    private static final int lengthOfMessage = 256;
    private String paramFilePath;
	
	public PTBREEngine(String paramFilePath) {
		super();
		this.paramFilePath = paramFilePath;
	}
	
	public PTBREKeyPair setup(int n) {
		PairingParameters paremeters = PairingFactory.getPairingParameters(paramFilePath);
		Pairing pairing = PairingFactory.getPairing(paremeters);
		
        Element gamma = pairing.getZr().newRandomElement().getImmutable()
        		,alpha = pairing.getZr().newRandomElement().getImmutable()
        		,epsilon  = pairing.getZr().newRandomElement().getImmutable();
        
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element v = g.powZn(gamma).getImmutable();
        Element[] gs = new Element[n * 2 + 1];
        
//        Element alphaI = pairing.getZr().newOneElement().getImmutable();
//        for (int i = 1; i < gs.length; i++) {
//        	alphaI = alphaI.powZn(alpha).getImmutable();
//        	if (i == n + 1) {
//                continue;
//            }
//            gs[i] = g.powZn(alphaI).getImmutable();
//        }
        
//        Element alphaI = pairing.getZr().newRandomElement();
        for (int i = 1; i < gs.length; i++) {
        	Element alphaI = alpha.powZn(pairing.getZr().newElement(BigInteger.valueOf((long)i))).getImmutable();
        	if (i == n + 1) {
                continue;
            }
            gs[i] = g.powZn(alphaI).getImmutable();
        }
        
        Element g_epsilon = g.powZn(epsilon).getImmutable();
        
		return new PTBREKeyPair(
				new PTBREPublicKey(paremeters, n, g, gs, v, g_epsilon),
				new PTBREMasterPrivateKey(paremeters, gamma));
	}

	public PTBREPrivateKey keyGen(PTBREKeyPair keyPair, int alice_idx) {
//		Element sk = keyPair.publicKey().gs[alice_idx].duplicate().powZn(keyPair.masterPrivateKey().sk()).getImmutable();
		Element sk = keyPair.publicKey().gs[alice_idx].getImmutable().powZn(keyPair.masterPrivateKey().sk()).getImmutable();
		
		return new PTBREPrivateKey(keyPair.publicKey().parameters(), sk);
	}

	public PTBRECipher encrypt(PTBREPublicKey pk, int[] S, byte[] m) {
		byte[] m_bytes = paddingLeadingZeroFromBytes(m);
        Element R = pk.pairing().getGT().newRandomElement().getImmutable();
        Element t = pk.H1(m_bytes, R);
        // calculete C = (C1, C2, C3, C4, C5, C6)
        Element C1 = R.mul(pk.pairing().pairing(pk.g1(), pk.gn()).powZn(t)).getImmutable();
        Element C2 = pk.g().powZn(t).getImmutable();
        Element C3 = pk.v().getImmutable();
        for (int j : S) {
            if (j > pk.n() || j < 1) {
                throw new IllegalArgumentException("Illegal index in the indexSet: " + j);
            }
            C3 = C3.mul(pk.gs()[pk.n() + 1 - j]).getImmutable();
        }
        C3 = C3.powZn(t).getImmutable();
        Element C4 = pk.g_epsilon().powZn(t).getImmutable();
        byte[] C5 = xor(m_bytes, pk.H2(R));
        Element C6 = pk.H3(C1, C2 ,C3, C4, C5).getImmutable();
        
		return new PTBRECipher(pk.parameters(), C1, C2, C3, C4, C5, C6);
	}
	
	public byte[] decrypt_1(PTBREPublicKey pk, PTBREPrivateKey sk_a, int idx, int[] indexSet, PTBRECipher C) {
        
        Element temp = sk_a.sk().getImmutable();
        for (int j : indexSet) {
            if (j == idx) continue;
            
            temp = temp.mul(pk.gs()[pk.n() + 1 - j + idx]).getImmutable();
        }
        Element gi = pk.gs()[idx].getImmutable();
        Element compute_R = C.C1().getImmutable().mul(pk.pairing().pairing(temp, C.C2())).div(pk.pairing().pairing(gi, C.C3())).getImmutable();
        byte[] reover_m = xor(C.C5(), pk.H2(compute_R));
        
        return removeLeadingZeroFromBytes(reover_m); //new String(removeLeadingZeroFromBytes(reover_m), StandardCharsets.UTF_8);
	}

	public KFrag[] rkGen(PTBREPublicKey pk, PTBREPrivateKey sk_a, int owner_idx, int[] S_prime, int N, int t) {
		
		Element s = pk.pairing().getZr().newRandomElement().getImmutable();
		Element u = pk.pairing().getZr().newRandomElement().getImmutable();
		byte[] sigma = paddingLeadingZeroFromBytes(UUID.randomUUID().toString().getBytes());
		Element R_prime = pk.pairing().getGT().newRandomElement().getImmutable();
		Element t_prime = pk.H1(sigma, R_prime).getImmutable();
		Element rk0 = sk_a.sk().mul(pk.g_epsilon().powZn(s)).getImmutable();
		Element rk1 = R_prime.mul(pk.pairing().pairing(pk.g1(), pk.gn()).powZn(t_prime)).getImmutable();
		Element rk2 = pk.g().powZn(t_prime).getImmutable();
		Element rk3 = pk.v().getImmutable();
        for (int j : S_prime) {
            if (j > pk.n() || j < 1) {
                throw new IllegalArgumentException("Illegal index in the indexSet: " + j);
            }
            rk3 = rk3.mul(pk.gs()[pk.n() + 1 - j]).getImmutable();
        }
        rk3 = rk3.powZn(t_prime).getImmutable();
        Element rk4 = pk.g().powZn(s).mul(pk.H4(sigma)).getImmutable();
        byte[] rk5 = xor(sigma, pk.H2(R_prime));
        Element rk6 = pk.H3(rk1, rk2, rk3, rk4, rk5).powZn(t_prime).getImmutable();
        Element rk7 = pk.g().powZn(u).getImmutable();
        PTBREReEncryptionKey rk = new PTBREReEncryptionKey(pk.parameters(), rk1, rk2, rk3, rk4, rk5, rk6, rk7);
		
        // handle secret sharing
		Element secret = rk0;
		Function<Element, Element> ssFn = genSecretSharingFunction(pk.pairing, N, t, secret);
		
//		System.out.println("rk0(secret):"+rk0);
		
		KFrag[] kfrags = new KFrag[N];
		Element rk_id, rk_x, rk_y;
		for(int i = 0 ;i<N;i++) {
			rk_id = pk.pairing().getZr().newRandomElement().getImmutable();
			
			rk_x = pk.H6(rk_id, t_prime);
			rk_y = ssFn.apply(rk_x);
			
			// should not put pairs in to rk (not need X)
			kfrags[i] = new KFrag(pk.parameters(), rk_id, rk_y, rk);
		}
		
		
		return kfrags;
	}
	
	public CFrag reEnc(PTBREPublicKey pk, KFrag kFrag, int owner_idx, int[] S,
			int[] S_prime, PTBRECipher C) {
		// TODO validate
		
		PTBREReEncryptionKey rk = kFrag.rk();
		
		Element C1_wave = C.C1().div(
					pk.pairing().pairing(pk.gs[owner_idx], C.C3())
					.mul(pk.pairing().pairing(rk.rk7(), C.C2())))
				.getImmutable();
		Element C2_wave = kFrag.rky().mul(rk.rk7()).getImmutable();

		for (int j : S) {			// original S or S'
			if (j == owner_idx) continue;
			C2_wave = C2_wave.mul(pk.gs()[pk.n() + 1 - j + owner_idx]).getImmutable();
		}
		
		CFrag cFrag = new CFrag(pk.parameters(), kFrag.rk_id(), 
//				kFrag.rky(), 
				C1_wave,C2_wave,C.C2(), C.C4(), C.C5()
				, rk.rk1(), rk.rk2(), rk.rk3(), rk.rk4(), rk.rk5(), rk.rk6());
		
		return cFrag;
	}
	
	public byte[] decrypt_2(PTBREPublicKey pk, PTBREPrivateKey sk_b, int alice_idx, int bob_idx, int[] S,
			int[] S_prime, CFrag[] cFrags) {
		Element g_new = pk.gs()[bob_idx].getImmutable();
		
		CFrag cFrag = cFrags[0];
		
		Element temp3 = sk_b.sk().getImmutable();
		for (int j : S_prime) {			// S'
		    if (j == bob_idx) continue;
		    
		    temp3 = temp3.mul(pk.gs()[pk.n() + 1 - j + bob_idx]).getImmutable();
		}
		Element compute_R_prime = cFrag.rk1().mul(pk.pairing().pairing(temp3, cFrag.rk2()).getImmutable()).div(pk.pairing().pairing(g_new, cFrag.rk3())).getImmutable();
		byte[] compute_sigma = xor(cFrag.rk5(), pk.H2(compute_R_prime));
		Element g_s = cFrag.rk4().div(pk.H4(compute_sigma)).getImmutable();
		Element compute_t_prime = pk.H1(compute_sigma, compute_R_prime);
		
		// validate
		Element validate_rk2 = pk.g().powZn(compute_t_prime).getImmutable();
		Element temp4 = pk.v().getImmutable();
		for (int j : S_prime) {			// S'
		    temp4 = temp4.mul(pk.gs()[pk.n() + 1 - j]).getImmutable();
		}
		Element validate_rk3 = temp4.powZn(compute_t_prime).getImmutable();
		Element validate_rk6 = pk.H3(cFrag.rk1(),cFrag.rk2(),cFrag.rk3(),cFrag.rk4(),cFrag.rk5()).powZn(compute_t_prime);
		
		// validate
		if(!PairingUtils.isEqualElement(cFrag.rk2(), validate_rk2)) {
			throw new RuntimeException("validate rk2 failed");
		}
		
		if(!PairingUtils.isEqualElement(cFrag.rk3(), validate_rk3)) {
			throw new RuntimeException("validate rk3 failed");
		}
		
		if(!PairingUtils.isEqualElement(cFrag.rk6(), validate_rk6)) {
			throw new RuntimeException("validate rk6 failed");
		}
		
//		Assert.assertTrue("validate rk2",PairingUtils.isEqualElement(cFrag.rk2(), validate_rk2));
//		Assert.assertTrue("validate rk3",PairingUtils.isEqualElement(cFrag.rk3(), validate_rk3));
//		Assert.assertTrue("validate rk6",PairingUtils.isEqualElement(cFrag.rk6(), validate_rk6));
		
		// compute real R, m
		BiFunction<Element[], Integer, Element> lagrange_fn = genLagrangeInterpolation(pk.pairing());
		
		Element[] X_set = new Element[cFrags.length];
		for(int i=0;i<cFrags.length;i++) {
			X_set[i] = pk.H6(cFrags[i].rk_id(), compute_t_prime);
		}
		
		Element temp = pk.pairing().getG1().newZeroElement().getImmutable();
		for(int i=0;i<cFrags.length;i++) {
			Element lamda = lagrange_fn.apply(X_set, i).getImmutable();
			temp = temp.add(cFrags[i].C2_wave().mulZn(lamda)).getImmutable();

		}
		
		Element C2_wave_prime = pk.pairing().pairing(temp, cFrag.C2());
		Element compute_R2 = cFrag.C1_wave().mul(C2_wave_prime).div(pk.pairing().pairing(cFrag.C4(),  g_s)).getImmutable();
		byte[] compute_m_bytes = xor(cFrag.C5(), pk.H2(compute_R2));
		
		Element compute_t = pk.H1(compute_m_bytes, compute_R2).getImmutable();
		Element validate_C4 = pk.g_epsilon().powZn(compute_t).getImmutable();
		
		// validate
		if(!PairingUtils.isEqualElement(cFrag.C4(), validate_C4)) {
			throw new RuntimeException("validate C4 failed");
		}
		// Assert.assertTrue("validate C4",PairingUtils.isEqualElement(cFrag.C4(), validate_C4));
		
		return removeLeadingZeroFromBytes(compute_m_bytes);
	}
	
	public static class CFrag   implements CipherParameters, Serializable {
		
		private PairingParameters parameters;
		private transient Pairing pairing;
		
		private transient Element rk_id;
		private final byte[] byteArrayRkId;
		
//		private Element rk_y;
		private transient Element C1_wave;
		private final byte[] byteArrayC1Wave;
		
		private transient Element C2_wave;
		private final byte[] byteArrayC2Wave;
		
		private transient Element C2;
		private final byte[] byteArrayC2;
		
		private transient Element C4;
		private final byte[] byteArrayC4;
		
		private byte[] C5;
		
		private transient Element rk1;
		private final byte[] byteArrayRk1;
		
		private transient Element rk2;
		private final byte[] byteArrayRk2;
		
		private transient Element rk3;
		private final byte[] byteArrayRk3;
		
		private transient Element rk4;
		private final byte[] byteArrayRk4;
		
		private byte[] rk5;
		
		private transient Element rk6;
		private final byte[] byteArrayRk6;
		
		
		public CFrag(PairingParameters parameters, Element id, 
				//Element rk_y, 
				Element c1_wave, Element c2_wave, Element c2, Element c4, byte[] c5, Element rk1, Element rk2, Element rk3, Element rk4,
				byte[] rk5, Element rk6) {
			super();
			
			this.parameters = parameters;
			this.pairing = PairingFactory.getPairing(parameters);
			
			this.rk_id = id;
			this.byteArrayRkId = this.rk_id.toBytes();
			
//			this.rk_y = rk_y;
			this.C1_wave = c1_wave;
			this.byteArrayC1Wave = this.C1_wave.toBytes();
			
			this.C2_wave = c2_wave;
			this.byteArrayC2Wave = this.C2_wave.toBytes();
			
			this.C2 = c2;
			this.byteArrayC2 = this.C2.toBytes();
			
			this.C4 = c4;
			this.byteArrayC4 = this.C4.toBytes();
			
			this.C5 = c5;
			
			this.rk1 = rk1;
			this.byteArrayRk1 = this.rk1.toBytes();
			
			this.rk2 = rk2;
			this.byteArrayRk2 = this.rk2.toBytes();
			
			this.rk3 = rk3;
			this.byteArrayRk3 = this.rk3.toBytes();
			
			this.rk4 = rk4;
			this.byteArrayRk4 = this.rk4.toBytes();
			
			this.rk5 = rk5;
			
			this.rk6 = rk6;
			this.byteArrayRk6 = this.rk6.toBytes();
		}
		
		public Element rk_id() {
			return rk_id;
		}
		
//		public Element rky() {
//			return rk_y;
//		}

		public Element C1_wave() {
			return C1_wave;
		}

		public Element C4() {
			return C4;
		}

		public byte[] C5() {
			return C5;
		}

		public Element rk1() {
			return rk1;
		}

		public Element rk2() {
			return rk2;
		}

		public Element rk3() {
			return rk3;
		}

		public Element rk4() {
			return rk4;
		}

		public byte[] rk5() {
			return rk5;
		}

		public Element rk6() {
			return rk6;
		}

		public Element C2_wave() {
			return C2_wave;
		}

		public Element C2() {
			return C2;
		}
		
		private void readObject(java.io.ObjectInputStream objectInputStream)
	            throws java.io.IOException, ClassNotFoundException {
	        objectInputStream.defaultReadObject();
	        
	        this.pairing = PairingFactory.getPairing(this.parameters);
	        this.rk_id = pairing.getZr().newElementFromBytes(this.byteArrayRkId).getImmutable();
	        this.C1_wave = pairing.getGT().newElementFromBytes(this.byteArrayC1Wave).getImmutable();
	        this.C2_wave = pairing.getG1().newElementFromBytes(this.byteArrayC2Wave).getImmutable();
	        this.C2 = pairing.getG1().newElementFromBytes(this.byteArrayC2).getImmutable();
	        this.C4 = pairing.getG1().newElementFromBytes(this.byteArrayC4).getImmutable();
	        this.rk1 = pairing.getGT().newElementFromBytes(this.byteArrayRk1).getImmutable();
	        this.rk2 = pairing.getG1().newElementFromBytes(this.byteArrayRk2).getImmutable();
	        this.rk3 = pairing.getG1().newElementFromBytes(this.byteArrayRk3).getImmutable();
	        this.rk4 = pairing.getG1().newElementFromBytes(this.byteArrayRk4).getImmutable();
	        this.rk6 = pairing.getG1().newElementFromBytes(this.byteArrayRk6).getImmutable();
	    }
		
	}

	
	public static class KFrag  implements CipherParameters, Serializable {
		private PairingParameters parameters;
		private transient Pairing pairing;
		
		private transient Element rk_id;
		private final byte[] byteArrayRkId;
		
		private transient Element rky;
		private final byte[] byteArrayRkY;
		
		private PTBREReEncryptionKey rk;
		
		public KFrag(PairingParameters parameters, Element rk_id, Element rky, PTBREReEncryptionKey rk) {
			super();
			
	        this.parameters = parameters;
			this.pairing = PairingFactory.getPairing(parameters);
			
			this.rk_id = rk_id;
			this.byteArrayRkId = this.rk_id.toBytes();
			
			this.rky = rky;
			this.byteArrayRkY = this.rky.toBytes();
			
			this.rk = rk;
		}
		
		public Element rk_id() {
			return rk_id;
		}

		public Element rky() {
			return rky;
		}
		
		public PTBREReEncryptionKey rk() {
			return rk;
		}
		
		private void readObject(java.io.ObjectInputStream objectInputStream)
	            throws java.io.IOException, ClassNotFoundException {
	        objectInputStream.defaultReadObject();
	        
	        this.pairing = PairingFactory.getPairing(this.parameters);
	        this.rk_id = pairing.getZr().newElementFromBytes(this.byteArrayRkId).getImmutable();
	        this.rky = pairing.getG1().newElementFromBytes(this.byteArrayRkY).getImmutable();
	    }
	}
	
	public static class PTBREReEncryptionKey implements CipherParameters, Serializable {
		
		private PairingParameters parameters;
		private transient Pairing pairing;
		
		private transient Element rk1;
		private final byte[] byteArrayRk1;
		
		private transient Element rk2;
		private final byte[] byteArrayRk2;
		
		private transient Element rk3;
		private final byte[] byteArrayRk3;
		
		private transient Element rk4;
		private final byte[] byteArrayRk4;
		
		private byte[] rk5;
		
		private transient Element rk6;
		private final byte[] byteArrayRk6;
		
		private transient Element rk7;
		private final byte[] byteArrayRk7;
		
		public PTBREReEncryptionKey(PairingParameters parameters, Element rk1, Element rk2, Element rk3, Element rk4, byte[] rk5,
				Element rk6, Element rk7) {
			super();
			
			this.parameters = parameters;
			this.pairing = PairingFactory.getPairing(parameters);
			
			this.rk1 = rk1;
			this.byteArrayRk1 = this.rk1.toBytes();
			
			this.rk2 = rk2;
			this.byteArrayRk2 = this.rk2.toBytes();
			
			this.rk3 = rk3;
			this.byteArrayRk3 = this.rk3.toBytes();
			
			this.rk4 = rk4;
			this.byteArrayRk4 = this.rk4.toBytes();
			
			this.rk5 = rk5;
			
			this.rk6 = rk6;
			this.byteArrayRk6 = this.rk6.toBytes();
			
			this.rk7 = rk7;
			this.byteArrayRk7 = this.rk7.toBytes();
		}

		public Element rk1() {
			return rk1;
		}

		public Element rk2() {
			return rk2;
		}

		public Element rk3() {
			return rk3;
		}

		public Element rk4() {
			return rk4;
		}

		public byte[] rk5() {
			return rk5;
		}

		public Element rk6() {
			return rk6;
		}
		
		public Element rk7() {
			return rk7;
		}
		
		private void readObject(java.io.ObjectInputStream objectInputStream)
	            throws java.io.IOException, ClassNotFoundException {
	        objectInputStream.defaultReadObject();
	        
	        this.pairing = PairingFactory.getPairing(this.parameters);
	        this.rk1 = pairing.getGT().newElementFromBytes(this.byteArrayRk1).getImmutable();
	        this.rk2 = pairing.getG1().newElementFromBytes(this.byteArrayRk2).getImmutable();
	        this.rk3 = pairing.getG1().newElementFromBytes(this.byteArrayRk3).getImmutable();
	        this.rk4 = pairing.getG1().newElementFromBytes(this.byteArrayRk4).getImmutable();
	        this.rk6 = pairing.getG1().newElementFromBytes(this.byteArrayRk6).getImmutable();
	        this.rk7 = pairing.getG1().newElementFromBytes(this.byteArrayRk7).getImmutable();
	    }
	}
	
	public static class PTBRECipher implements CipherParameters, Serializable {
		
		private PairingParameters parameters;
		private transient Pairing pairing;
		
		private transient Element C1;		// G2
		private final byte[] byteArrayC1;
		
		private transient Element C2;		// G1
		private final byte[] byteArrayC2;
		
		private transient Element C3;		// G1
		private final byte[] byteArrayC3;
		
		private transient Element C4;		// G1
		private final byte[] byteArrayC4;
		
		private byte[] C5;
		
		private transient Element C6;		// G1
		private final byte[] byteArrayC6;
		
		public PTBRECipher(PairingParameters parameters, Element c1, Element c2, Element c3, Element c4, byte[] c5, Element c6) {
			super();
			
			this.parameters = parameters;
			this.pairing = PairingFactory.getPairing(parameters);
			
			this.C1 = c1;
			this.byteArrayC1 = this.C1.toBytes();
			
			this.C2 = c2;
			this.byteArrayC2 = this.C2.toBytes();
			
			this.C3 = c3;
			this.byteArrayC3 = this.C3.toBytes();
			
			this.C4 = c4;
			this.byteArrayC4 = this.C4.toBytes();
			
			this.C5 = c5;
			
			this.C6 = c6;
			this.byteArrayC6 = this.C6.toBytes();
		}

		public Element C1() {
			return C1;
		}

		public Element C2() {
			return C2;
		}

		public Element C3() {
			return C3;
		}

		public Element C4() {
			return C4;
		}

		public byte[] C5() {
			return C5;
		}

		public Element C6() {
			return C6;
		}
		
		private void readObject(java.io.ObjectInputStream objectInputStream)
	            throws java.io.IOException, ClassNotFoundException {
	        objectInputStream.defaultReadObject();
	        
	        this.pairing = PairingFactory.getPairing(this.parameters);
	        this.C1 = pairing.getGT().newElementFromBytes(this.byteArrayC1).getImmutable();
	        this.C2 = pairing.getG1().newElementFromBytes(this.byteArrayC2).getImmutable();
	        this.C3 = pairing.getG1().newElementFromBytes(this.byteArrayC3).getImmutable();
	        this.C4 = pairing.getG1().newElementFromBytes(this.byteArrayC4).getImmutable();
	        this.C6 = pairing.getG1().newElementFromBytes(this.byteArrayC6).getImmutable();
	    }
		
	}

	public static class PTBREKeyPair{
		private PTBREPublicKey publicKey;
		private PTBREMasterPrivateKey masterPrivateKey;
		
		public PTBREKeyPair(PTBREPublicKey publicKey, PTBREMasterPrivateKey ptbreMasterPrivateKey) {
			super();
			this.publicKey = publicKey;
			this.masterPrivateKey = ptbreMasterPrivateKey;
		}

		public PTBREPublicKey publicKey() {
			return publicKey;
		}

		public PTBREMasterPrivateKey masterPrivateKey() {
			return masterPrivateKey;
		}
		
		
	}
	
	public static class PTBREPublicKey implements CipherParameters, Serializable {
		
		private PairingParameters parameters;
		private transient Pairing pairing;
		
		private int n;
		
		
		private transient Element g;
		private final byte[] byteArrayG;
		
		private transient Element[] gs;
		private final byte[][] byteArraysGs;
		
		private transient Element v;
		private final byte[] byteArrayV;
		
		private transient Element g_epsilon;
		private final byte[] byteArrayGepsilon;
		
		public PTBREPublicKey(PairingParameters paremeters, int n, Element g, Element[] gs, Element v, Element g_epsilon) {
			this.n = n;
			this.parameters = paremeters;
			this.pairing = PairingFactory.getPairing(paremeters);
			this.g = g;
			this.byteArrayG = this.g.toBytes();
			
			this.gs = gs;
			this.byteArraysGs = PairingUtils.GetElementArrayBytes(this.gs);
			
			this.v = v;
			this.byteArrayV = this.v.toBytes();
			
			this.g_epsilon = g_epsilon;
			this.byteArrayGepsilon = this.g_epsilon.toBytes();
		}

		public Pairing pairing() {
			return pairing;
		}
		
		public int n() {
			return n;
		}

		public Element g() {
			return g;
		}

		public Element[] gs() {
			return gs;
		}

		public Element v() {
			return v;
		}

		public Element g_epsilon() {
			return g_epsilon;
		}
		
		public Element g1() {
			return gs[1].getImmutable();
		}
		
		public Element gn() {
			return gs[n].getImmutable();
		}
		
		public PairingParameters parameters() {
			return parameters;
		}
		
		// h1 : {0, 1}^k × G2 → Zp
		public Element H1(byte[] messageBytes, Element g2) {
			
			byte[] c = concat(messageBytes,g2.toBytes());
			
			return PairingUtils.MapByteArrayToGroup(pairing, c, PairingGroupType.Zr);
		}
		
		// H2 : G2 → {0, 1}^k
		public byte[] H2(Element g2) {
			return paddingLeadingZeroFromBytes(PairingUtils.hash(g2.toBytes()));
		}
		
		// H3 : G2 × G1 × G1 × G1 × {0, 1}k → G1
		public Element H3(Element g2, Element g1_1, Element g1_2, Element g1_3, byte[] messageBytes) {
			byte[] c = concat(concat(concat(concat(g2.toBytes(), g1_1.toBytes()), g1_2.toBytes()), g1_3.toBytes()), messageBytes);
			
			return PairingUtils.MapByteArrayToGroup(pairing, c, PairingGroupType.G1);
		}
		
		// H4 : {0, 1}^k → G1
		public Element H4(byte[] messageBytes) {
			
			return PairingUtils.MapByteArrayToGroup(pairing, messageBytes, PairingGroupType.G1);
		}
		
		// H5 : Zp∗ → Zp
		public Element H5(Element Zp) {
			
			return PairingUtils.MapByteArrayToGroup(pairing, Zp.toBytes(), PairingGroupType.Zr);
		}
		
		// H6 : Zp∗, Zp∗ → Zp
		public Element H6(Element z1, Element z2) {
			Element hash_z1 = PairingUtils.MapByteArrayToGroup(pairing, z1.toBytes(), PairingGroupType.Zr);
			Element hash_z2 = PairingUtils.MapByteArrayToGroup(pairing, z2.toBytes(), PairingGroupType.Zr);
			
			byte[] c = concat(hash_z1.toBytes(), hash_z2.toBytes());
			
			return PairingUtils.MapByteArrayToGroup(pairing, c, PairingGroupType.Zr);
		}
		
		private void readObject(java.io.ObjectInputStream objectInputStream)
	            throws java.io.IOException, ClassNotFoundException {
	        objectInputStream.defaultReadObject();
	        
	        this.pairing = PairingFactory.getPairing(this.parameters);
	        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
	        this.gs = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysGs, PairingUtils.PairingGroupType.G1);
	        this.v = pairing.getG1().newElementFromBytes(this.byteArrayV).getImmutable();
	        this.g_epsilon = pairing.getG1().newElementFromBytes(this.byteArrayGepsilon).getImmutable();
	    }
		
	}
	
	public static class PTBREMasterPrivateKey implements CipherParameters, Serializable {
		
		private PairingParameters parameters;
		private transient Pairing pairing;
		
		private transient Element msk;
		private final byte[] byteArrayMsk;
		
		public PTBREMasterPrivateKey(PairingParameters paremeters, Element msk) {
			this.parameters = paremeters;
			this.pairing = PairingFactory.getPairing(paremeters);
			
			this.msk = msk;
			byteArrayMsk = this.msk.toBytes();
		}

		public Element sk() {
			return msk;
		}
		
		private void readObject(java.io.ObjectInputStream objectInputStream)
	            throws java.io.IOException, ClassNotFoundException {
	        objectInputStream.defaultReadObject();
	        
	        this.pairing = PairingFactory.getPairing(this.parameters);
	        this.msk = pairing.getZr().newElementFromBytes(this.byteArrayMsk).getImmutable();
	    }
		
	}
	
	public static class PTBREPrivateKey implements CipherParameters, Serializable {
		
		private PairingParameters parameters;
		private transient Pairing pairing;
		
		private transient Element sk;
		private final byte[] byteArraySk;
		
		public PTBREPrivateKey(PairingParameters paremeters, Element sk) {
			this.parameters = paremeters;
			this.pairing = PairingFactory.getPairing(paremeters);
			
			this.sk = sk;
			byteArraySk = this.sk.toBytes();
		}

		public Element sk() {
			return sk;
		}
		
		private void readObject(java.io.ObjectInputStream objectInputStream)
	            throws java.io.IOException, ClassNotFoundException {
	        objectInputStream.defaultReadObject();
	        
	        this.pairing = PairingFactory.getPairing(this.parameters);
	        this.sk = pairing.getG1().newElementFromBytes(this.byteArraySk).getImmutable();
	    }
		
	}
	
	public static byte[] concat(byte[] a, byte[] b) {
		byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		
		return c;
	}
	
	
	private byte[] xor(byte[] a, byte[] b) {
		if(a.length != b.length)
			throw new RuntimeException("The length of bytes should be the same.");
		
		byte[] c = new byte[a.length];
		
		for(int i = 0;i<a.length;i++) {
			c[i] = (byte) (a[i] ^ b[i]);
		}
		
//		byte[] c;
//		int minLength;
//		
//		if(a.length > b.length) {
//			minLength = b.length;
//			c = new byte[a.length];
//			System.arraycopy(a, 0, c, 0, a.length);
//		}else {
//			minLength = a.length;
//			c = new byte[b.length];
//			System.arraycopy(b, 0, c, 0, b.length);
//		}
//		
//		for(int i = 0;i<minLength;i++) {
//			c[i] = (byte) (a[i] ^ b[i]);
//		}
			
		return c;
	}
	
	
	private static byte[] paddingLeadingZeroFromBytes(byte[] mBytes) {
		
		if(mBytes.length > lengthOfMessage)
			throw new RuntimeException("The length of message bytes should be below the length k=" +lengthOfMessage);
		
		byte[] c = new byte[lengthOfMessage];
		
		System.arraycopy(mBytes, 0, c, lengthOfMessage-mBytes.length, mBytes.length);
		
		return c;
	}
	
	// remove leading zero from bytes
	public static byte[] removeLeadingZeroFromBytes(byte[] arr){
        int count = 0;

        for(int i = 0;i<arr.length-1;i++)
        {

            if(arr[i]>0){          
                break;
            }
            count++;
        }

        byte [] output = new byte[arr.length-count];
        for(int i = 0;i<output.length;i++) {
            output[i] = arr[i+count];
        }
        return output; 
    }
	
	public BiFunction<Element[], Integer, Element> genLagrangeInterpolation(Pairing pairing) {
		BiFunction<Element[], Integer,  Element> lagrange_function = (pairs, i) -> {
			Element lagrange_reuslt = pairing.getZr().newElement(BigInteger.valueOf(1));
			
			Element x_i = pairs[i];// .getId();
			
			for(int j=0;j<pairs.length;j++) {
				
				if(j==i)
					continue;
				
				
				Element x_j = pairs[j];//.getId();
				Element lagrange_i_reuslt = x_j.div(x_j.sub(x_i)).getImmutable();
				lagrange_reuslt = lagrange_reuslt.mul(lagrange_i_reuslt);
			}
			
			return lagrange_reuslt;
		};
		
		return lagrange_function;
	}
	
	public Function<Element,Element> genSecretSharingFunction(Pairing pairing,int N,  int t, Element secretOnG1) {
		
		if(t<=0 || t>=N)
			throw new RuntimeException("threshold t should be in (0,N)");
		
		Element[] coefficients = new Element[t-1];
		
		for(int i=0;i<t-1;i++) {
			coefficients[i] = pairing.getG1().newRandomElement().getImmutable();
		}
		
		Function<Element, Element> f_o_x = x -> {
			Element a0 = secretOnG1.getImmutable();
			
			for(int i=1;i<=coefficients.length;i++) {
				Element a = coefficients[i-1];
//				System.out.println("index:"+i +" ,"+a);
				
				a0 = a0.add(a.mulZn(x.pow(BigInteger.valueOf(i)))).getImmutable();
			}
			
			return a0;
		} ;
		
		return f_o_x;
	}
	
}
