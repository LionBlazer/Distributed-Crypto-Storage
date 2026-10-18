// Public test TLS identities only; these are not BFV or owner authorization keys.
pub(in crate::opening) fn identity() -> peer_runtime::Identity {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
    let mut params = CertificateParams::new(vec!["dcs-peer".into()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    peer_runtime::Identity {
        certificate: certificate.der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    }
}
