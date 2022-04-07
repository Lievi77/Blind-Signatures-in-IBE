package cryptid.ibe;

import cryptid.ellipticcurve.point.affine.AffinePoint;
import cryptid.ibe.domain.CipherTextTuple;
import cryptid.ibe.domain.PrivateKey;
import cryptid.ibe.domain.PublicParameters;

import java.util.Objects;
import java.util.Optional;

/**
 * Convenience class that can be used to perform encrypt, decrypt and extract operations.
 */
public class IdentityBasedEncryption {
    private final IbeClient client;
    private final PrivateKeyGenerator privateKeyGenerator;
    private final PublicParameters publicParameters;
    /**
     * Constructs a new instance using the specified components.
     * @param client the client that will be used for encryption and decryption
     * @param privateKeyGenerator the PKG which will provide extract capapbilities
     */
    public IdentityBasedEncryption(final IbeClient client, final PrivateKeyGenerator privateKeyGenerator, final PublicParameters publicParameters) {
        this.client = Objects.requireNonNull(client);
        this.privateKeyGenerator = Objects.requireNonNull(privateKeyGenerator);
        this.publicParameters = Objects.requireNonNull(publicParameters);
    }

    /**
     * Encrypts the specified message using the provided identity.
     * @param message the message to encrypt
     * @param identity the identity of the receiver
     * @return the ciphertext
     */
    public CipherTextTuple encrypt(final String message, final AffinePoint identity) {
        return client.encrypt(message, identity);
    }

    /**
     * Decrypts the specified ciphertext with the specified private key. If the decryption if successful,
     * an Optional with the result is returned. However, if the decryption fails, then an empty Optional
     * is returned.
     * @param privateKey the private key
     * @param ciphertext the ciphertext to decrypt
     * @return an Optional with the plaintext result of the decryption or an empty Optional on failure
     */
    public Optional<String> decrypt(final PrivateKey privateKey, final CipherTextTuple ciphertext) {
        return client.decrypt(privateKey, ciphertext);
    }

    /**
     * Extracts the private key corresponding to the specified identity.
     * @param identity the identity whose private key should be extracted
     * @return the private key corresponding to the identity
     */
    public PrivateKey extract(final AffinePoint identity) {
        return privateKeyGenerator.extract(identity);
    }

    /*
    * Addition by Lev C. G. A.
    *
    *  Getter for systemParameters
    *
     */
    public PublicParameters getPublicParameters(){
        return publicParameters;
    }
}
