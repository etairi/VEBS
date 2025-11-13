use bls12_381::{
    pairing,
    G1Affine,
    G2Affine,
    G2Projective,
    Scalar
};
use bls12_381::{
    hash_to_curve::{
        ExpandMsgXmd,
        HashToCurve
    },
};
use sha2::{Sha256};
use rand::rngs::OsRng;
use ff::Field;

// BLS signature scheme, blind BLS Signature scheme, BLS VES, BLS VEBS
pub struct BLSKeyPair {
    sk: Scalar,
    pub pk: (G1Affine, G2Affine),
}

pub struct BLSPublic {
    pub pk: (G1Affine, G2Affine)
}

pub struct BLSUserState {
    state: Scalar,
    pub pk: (G1Affine, G2Affine)
}

pub struct BLSAdjKey {
    sk: Scalar,
    pub pk: (G1Affine, G2Affine)
}

impl BLSKeyPair {
    pub fn new() -> BLSKeyPair{
        let sk =  Scalar::random(&mut OsRng);
        let pka = G1Affine::from(G1Affine::generator() * sk);
        let pkb = G2Affine::from(G2Affine::generator() * sk);
        let pk = (pka, pkb);

        BLSKeyPair {
            sk,
            pk,
        }
    }

    pub fn public(&self) -> BLSPublic{
        let pk = &self.pk;
        BLSPublic {
            pk: *pk
        }
    }

    // BLS signature
    pub fn sign(&self, m: &str)-> G2Affine {
        G2Affine::from(hash_to_g2(m) * &self.sk)
    }

    // BLS blind signature
    pub fn signer(&self, rho_u: &G2Affine) -> G2Affine {
        G2Affine::from(rho_u * &self.sk)
    }

    // BLS VES
    pub fn vesign(&self, apk: &(G1Affine, G2Affine), m: &str) -> (G2Affine, G2Affine) {
        let sigma = &self.sign(m);
        let r =  Scalar::random(&mut OsRng);
        let mu = G2Affine::from(G2Affine::generator() * &r);
        let v = G2Affine::from(apk.1 * &r);
        let omega = G2Projective::from(sigma) + G2Projective::from(v);

        (
            G2Affine::from(omega),
            mu
        )
    }

    // BLS VEBS
    pub fn vebsign(&self, apk: &(G1Affine, G2Affine), rho_u: &G2Affine )-> (G2Affine, G2Affine) {
        let rho_s = &self.signer(rho_u);
        let r =  Scalar::random(&mut OsRng);
        let mu = G2Affine::from(G2Affine::generator() * &r);
        let v = G2Affine::from(apk.1 * &r);

        let omega = G2Projective::from(rho_s) + G2Projective::from(v);

        (
            G2Affine::from(omega),
            mu
        )
    }
}

impl BLSPublic {
    pub fn check(&self) ->() {
        // Check that pk is valid
        let left = pairing(&G1Affine::generator(), &self.pk.1);
        let right = pairing(&self.pk.0, &G2Affine::generator());
        assert!(left == right, "Signer PK is invalid");
    }

    pub fn verify(&self, m: &str, s: &G2Affine) -> () {
        let gt = pairing(&G1Affine::generator(), s);
        let expected = pairing(&self.pk.0, &hash_to_g2(m));    
        assert!(gt == expected, "Invalid BLS signature");
    }

    pub fn ves_verify(&self, apk: &(G1Affine, G2Affine), m: &str, omega: &(G2Affine, G2Affine)) -> () {
        let a = pairing(&G1Affine::generator(), &omega.0);
        let b = pairing(&self.pk.0, &hash_to_g2(m));
        let c = pairing(&apk.0, &omega.1);
        assert!(a == b + c, "Invalid VES BLS signature");
    }

    pub fn vebs_verify(&self, apk: &(G1Affine, G2Affine), rho_u: &G2Affine, omega: &(G2Affine, G2Affine)) -> () {
        let a = pairing(&G1Affine::generator(), &omega.0);
        let b = pairing(&self.pk.0, &rho_u);
        let c = pairing(&apk.0, &omega.1);
        assert!(a == b + c, "Invalid VEBS BLS signature");
    }
}

impl BLSUserState{
    pub fn user(pk: &BLSPublic, m: &str) -> (BLSUserState, G2Affine) {
        let state =  Scalar::random(&mut OsRng);
        let blind = G2Affine::from(G2Affine::generator() * &state);
        let rho_u = G2Projective::from(hash_to_g2(m)) + G2Projective::from(blind);
        let rho_u = G2Affine::from(rho_u);       

        (
            BLSUserState{
                state,
                pk: pk.pk
            },
            G2Affine::from(rho_u)
        )        
    }

    pub fn derive(&self, rho_s: &G2Affine) -> G2Affine{
        let phi_r = G2Projective::from(&self.pk.1*&self.state);
        let sigma = G2Projective::from(rho_s) - phi_r;
        G2Affine::from(sigma)
    }
}

impl BLSAdjKey {
    pub fn new() -> BLSAdjKey{
        let sk =  Scalar::random(&mut OsRng);
        let pka = G1Affine::from(G1Affine::generator() * sk);
        let pkb = G2Affine::from(G2Affine::generator() * sk);
        let pk = (pka, pkb);

        BLSAdjKey {
            sk,
            pk,
        }
    }

    pub fn ves_resolve(&self, _m: &str, _pk: &BLSPublic, omega: &(G2Affine, G2Affine)) -> G2Affine {
        let mu_ask = G2Affine::from(omega.1 * &self.sk);
        let sigma = G2Projective::from(omega.0) - G2Projective::from(mu_ask);

        G2Affine::from(sigma)
    }

    pub fn vebs_resolve(&self,_rho_u: &G2Affine, _pk: &BLSPublic,   omega: &(G2Affine, G2Affine))-> G2Affine {
        let mu_ask = G2Affine::from(omega.1 * &self.sk);
        let rho_s = G2Projective::from(omega.0) - G2Projective::from(mu_ask);

        G2Affine::from(rho_s)
    }
}

// Tools
pub fn hash_to_g2(m: &str) -> G2Affine {
    let g = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::encode_to_curve(
        m.as_bytes(),
        b"BLS-sign"
    );
    let aff = G2Affine::from(g);

    aff
}