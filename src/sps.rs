use bls12_381::{
    pairing,
    G1Projective,
    G1Affine,
    G2Projective,
    G2Affine,
    Gt,
    Scalar
};
use bls12_381::{
    hash_to_curve::{
        ExpandMsgXmd,
        HashToCurve
    },
};
use rand::{
    RngCore,
    rngs::OsRng
};
use sha2::{Sha256};
use ff::Field;

pub const NONCE_LENGTH: usize = 32;
pub const TAG_LENGTH: usize = 16;

#[derive(Clone)]
pub struct SPSKeyPair {
    sk: Vec<Scalar>,
    pub pk: Vec<G2Affine>,
}

pub struct SPSSignature {
    pub z1: G1Affine,
    pub y1: G1Affine,
    pub y2: G2Affine,
    pub v2: G2Affine
}

pub struct SPSPublic {
    pub pk: Vec<G2Affine>
}

pub struct SPSReceiverKey {
    pub sk: Scalar,
    pub pk: G1Affine
}

pub struct SPSAdjKey {
    pub sk: Scalar,
    pub pk: G1Affine
}

// This is \widetilde{\omega} in Figure 11 of our paper.
pub struct SPSEncryptedSignature {
    pub omega: G1Affine,
    pub rho: G1Affine,
    pub y1: G1Affine,
    pub y2: G2Affine,
    pub y2_prime: G2Affine,
    pub v2: G2Affine
}

impl SPSKeyPair {
    pub fn new(l:usize) -> SPSKeyPair{
        let (sk, pk): (Vec<Scalar>, Vec<G2Affine>) = (0..l)
        .map(|_|{
            let a = Scalar::random(&mut OsRng);
            let b = G2Affine::from(G2Affine::generator() * a);
            (a, b)
        })
        .collect();

        SPSKeyPair {
            sk,
            pk,
        }
    }
    
    pub fn public(&self) -> SPSPublic{
        let pk = &self.pk;

        SPSPublic {
            pk: pk.clone()
        }
    }

    // SPS eq sign
    pub fn sign(&self, m: &Vec<&G1Affine>, t: &[u8]) -> SPSSignature {
        let l = self.sk.len();
        assert!(l == m.len(), "Different vector lengths");
        assert!(t.len() == TAG_LENGTH, "Invalid tag length");

        let y = Scalar::random(&mut OsRng);
        let inv_y = y.invert().unwrap();
        let mut z= G1Projective::identity();
        
        for i in 0..l {
            z = z + G1Projective::from(m[i] * self.sk[i]);
        }

        let z1 = G1Affine::from(z * y);
        let y1 = G1Affine::from(G1Affine::generator() * inv_y);
        let y2 = G2Affine::from(G2Affine::generator() * inv_y);

        let tag = hash_to_g2(t);
        let v2 = G2Affine::from(tag * inv_y);

        SPSSignature{
            z1,
            y1,
            y2,
            v2
        }
    }

    // SPS Issue (non-interactive blind signature)
    pub fn issue(&self, rpk: &G1Affine, t: &[u8]) -> (SPSSignature, [u8; NONCE_LENGTH]) {
        assert!(self.sk.len() == 2, "Invalid signing key length");
        assert!(t.len() == TAG_LENGTH, "Invalid tag length");

        let mut rng = OsRng;
        let mut nonce = [0u8; NONCE_LENGTH];
        rng.fill_bytes(&mut nonce);

        let h = hash_to_g1(&nonce);
        let mut m = Vec::new();

        m.push(rpk);
        m.push(&h);
        let psig = self.sign(&m, t);

        (psig, nonce.clone())
    }

    // SPS VENIBS
    pub fn venibs_sign(&self, rpk: &G1Affine, apk: &G1Affine, t: &[u8]) -> (SPSEncryptedSignature, [u8; NONCE_LENGTH]) {
        let (psig, nonce) = self.issue(rpk, t);

        let r = Scalar::random(&mut OsRng);
        let rho = G1Affine::from(G1Affine::generator() * r);
        let y2_prime = G2Affine::from(&psig.y2 * r);
        let nu = G1Affine::from(apk * r);
        let omega = G1Projective::from(psig.z1) + G1Projective::from(nu);

        let omega_tilde = SPSEncryptedSignature {
            omega: G1Affine::from(omega),
            rho,
            y1: psig.y1,
            y2: psig.y2,
            y2_prime,
            v2: psig.v2
        };

        (omega_tilde, nonce.clone())
    }

    pub fn venibs_sign_tricky(&self, rpk: &G1Affine, apk: &G1Affine, t: &[u8]) -> (SPSSignature, [u8; NONCE_LENGTH]) {
        let rpk_prime = G1Projective::from(rpk) + G1Projective::from(apk);

        self.issue(&G1Affine::from(rpk_prime), t)
    }
}

impl SPSSignature {
    pub fn change_representation(&self, mu: &Scalar, _m: &Vec<&G1Affine>) -> SPSSignature{
        let phi = Scalar::random(&mut OsRng);
        let inv_phi = phi.invert().unwrap();
        let phi_mu = mu * phi;

        let z1 = G1Affine::from(self.z1 * phi_mu);
        let y1 = G1Affine::from(self.y1 * inv_phi);
        let y2 = G2Affine::from(self.y2 * inv_phi);
        let v2 = G2Affine::from(self.v2 * inv_phi);

        SPSSignature{
            z1,
            y1,
            y2,
            v2
        }
    }
}

impl SPSPublic {
    pub fn verify(&self, m: &Vec<&G1Affine>, t: &[u8], sig: &SPSSignature) -> (){
        let l = self.pk.len();
        assert!(l == m.len(), "Different vector lengths");
        assert!(t.len() == TAG_LENGTH, "Invalid tag length");

        let mut b1_left= Gt::identity();
        for i in 0..l {
            b1_left = b1_left + pairing(&m[i], &self.pk[i]);
        }
        let b1_right = pairing(&sig.z1, &sig.y2);
        
        let b2_left = pairing(&sig.y1, &G2Affine::generator());
        let b2_right = pairing(&G1Affine::generator(), &sig.y2);

        let b3_left = pairing(&G1Affine::generator(), &sig.v2);
        let b3_right = pairing(&sig.y1, &hash_to_g2(t));

        assert!(b1_left == b1_right, "SPS signature verification failed");
        assert!(b2_left == b2_right, "SPS signature verification failed");
        assert!(b3_left == b3_right, "SPS signature verification failed");
    }

    pub fn nibs_verify(&self, m: &G1Affine, t: &[u8], sig: &SPSSignature) -> (){
        assert!(t.len() == TAG_LENGTH, "Invalid tag length");

        let mut msg: Vec<_> = Vec::new(); 
        let step = G1Affine::generator();
        msg.push(&step);
        msg.push(m);

        self.verify(&msg, t, sig)
    }

    pub fn venibs_verify(&self, rpk: &G1Affine, apk: &G1Affine, nonce: &[u8], t: &[u8], tilde_omega: &SPSEncryptedSignature) -> () {
        assert!(nonce.len() == NONCE_LENGTH, "Invalid nonce length");
        assert!(t.len() == TAG_LENGTH, "Invalid tag length");
        assert!(self.pk.len() == 2, "Invalid public key length");

        let pair_rpk_pk = pairing(&rpk, &self.pk[0]);
        let pair_nonce_pk = pairing(&hash_to_g1(nonce), &self.pk[1]);
        let pair_apk_y2_prime = pairing(&apk, &tilde_omega.y2_prime);
        let b1_left = pair_rpk_pk + pair_nonce_pk + pair_apk_y2_prime;
        let b1_right = pairing(&tilde_omega.omega, &tilde_omega.y2);

        let b2_left = pairing(&tilde_omega.y1, &G2Affine::generator());
        let b2_right = pairing(&G1Affine::generator(), &tilde_omega.y2);

        let b3_left = pairing(&G1Affine::generator(), &tilde_omega.v2);
        let b3_right = pairing(&tilde_omega.y1, &hash_to_g2(t));

        let b4_left = pairing(&tilde_omega.rho, &tilde_omega.y2);
        let b4_right = pairing(&G1Affine::generator(), &tilde_omega.y2_prime);

        assert!(b1_left == b1_right, "VENIBS verification failed");
        assert!(b2_left == b2_right, "VENIBS verification failed");
        assert!(b3_left == b3_right, "VENIBS verification failed");
        assert!(b4_left == b4_right, "VENIBS verification failed");
    }

    pub fn venibs_verify_tricky(&self, rpk: &G1Affine, apk: &G1Affine, nonce: &[u8], t: &[u8], omega: &SPSSignature) -> () {
        assert!(nonce.len() == NONCE_LENGTH, "Invalid nonce length");
        assert!(t.len() == TAG_LENGTH, "Invalid tag length");

        let rpk_prime = G1Projective::from(rpk) + G1Projective::from(apk);
        let rpk_prime_affine = G1Affine::from(rpk_prime);
        let mut m_rpk_prime_rep = Vec::new();

        let m_nonce = hash_to_g1(nonce);
        m_rpk_prime_rep.push(&rpk_prime_affine);
        m_rpk_prime_rep.push(&m_nonce);

        self.verify(&m_rpk_prime_rep, t, &omega)
    }

}

impl SPSReceiverKey {
    pub fn new() -> SPSReceiverKey {
        let sk =  Scalar::random(&mut OsRng);
        let pk = G1Affine::from(G1Affine::generator() * sk);

        SPSReceiverKey{
            sk,
            pk
        }
    }

    pub fn combine(&self, ask: &Scalar) -> SPSReceiverKey{
        let sk = &self.sk + ask;
        let pk = G1Affine::from(G1Affine::generator() * sk);

        SPSReceiverKey{
            sk,
            pk
        }
    }

    pub fn obtain(&self, pk: &SPSPublic, psig: &SPSSignature, nonce: &[u8], t: &[u8]) -> (SPSSignature, G1Affine) {
        assert!(pk.pk.len() == 2, "Invalid public key length");
        assert!(nonce.len() == NONCE_LENGTH, "Invalid nonce length");
        assert!(t.len() == TAG_LENGTH, "Invalid tag length");

        // verify if psig is valid in the rpk representation
        let mut msg = Vec::new();
        let h = hash_to_g1(nonce);
        msg.push(&self.pk);
        msg.push(&h);

        pk.verify(&msg, t, &psig);

        // If it verifies, change representation
        let inv_rsk = &self.sk.invert().unwrap();
        let mu = G1Affine::from(h * inv_rsk);

        let mut m = Vec::new(); 
        m.push(&self.pk);
        m.push(&h);

        let sig = psig.change_representation( &inv_rsk, &m);

        (sig, mu)

    }

    pub fn venibs_resolve(&self, ask: &Scalar, pk: &SPSPublic, tilde_omega: &SPSEncryptedSignature, nonce: &[u8], t: &[u8]) -> SPSSignature {
        let apk = G1Affine::from(G1Affine::generator() * ask);
        pk.venibs_verify(&self.pk, &apk, nonce, t, tilde_omega);

        let nu = G1Affine::from(tilde_omega.rho * ask);
        let z1 = G1Projective::from(tilde_omega.omega) - G1Projective::from(nu);

        SPSSignature { 
            z1: G1Affine::from(z1),
            y1: tilde_omega.y1, 
            y2: tilde_omega.y2,
            v2: tilde_omega.v2
        }
    }

    pub fn venibs_resolve_obtain(&self, ask: &Scalar, pk: &SPSPublic, tilde_omega: &SPSEncryptedSignature, nonce: &[u8], t: &[u8]) -> (SPSSignature, G1Affine) {
        let apk = G1Affine::from(G1Affine::generator() * ask);
        pk.venibs_verify(&self.pk, &apk, nonce, t, tilde_omega);

        let nu = G1Affine::from(tilde_omega.rho * ask);
        let z1 = G1Projective::from(tilde_omega.omega) - G1Projective::from(nu);

        let psig = SPSSignature { 
            z1: G1Affine::from(z1),
            y1: tilde_omega.y1, 
            y2: tilde_omega.y2,
            v2: tilde_omega.v2
        };

        self.obtain(pk, &psig, nonce, t)
    }

    pub fn venibs_resolve_obtain_tricky(&self, ask: &Scalar, pk: &SPSPublic, psig: &SPSSignature, nonce: &[u8], t: &[u8]) -> (SPSSignature, G1Affine) {
        let rsk_prime = self.combine(ask);

        rsk_prime.obtain(pk, psig, nonce, t)
    }
}

impl SPSAdjKey {
    pub fn new() -> SPSAdjKey {
        let sk =  Scalar::random(&mut OsRng);
        let pk = G1Affine::from(G1Affine::generator() * sk);

        SPSAdjKey{
            sk,
            pk
        }
    }
}

pub fn hash_to_g1(msg: &[u8]) -> G1Affine {
    let point = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        msg,
        b"BLS12-381-G1:SHA-256"
    );
    let aff = G1Affine::from(point);

    aff
}

pub fn hash_to_g2(msg: &[u8]) -> G2Affine {
    let point = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        msg,
        b"BLS12-381-G2:SHA-256"
    );
    let aff = G2Affine::from(point);

    aff
}
