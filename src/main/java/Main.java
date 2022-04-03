import cryptid.ibe.IdentityBasedEncryption;

public class Main{
    public static void main(String[] args) throws Exception{
        /*
            Create Bob and PKG
            Take message input from Bob alongside public key
            Pass Bob info to PKG to create Ciphertext
            Pass Ciphertext to Alice
            Alice requests private key, decrypts
            Print message to confirm
         */

        System.out.println("~~ Setup ~~");
        //Create PKG/IBE wrapper class for issuing private keys
        System.out.println("Creating PKG...");
        PKG pkg = new PKG();
        //Get instance of IBE in wrapper class for use in encrypting
        IdentityBasedEncryption ibe = pkg.getInstance();

        System.out.println("Creating CA...");
        CA certificateAuthority = new CA();
        Utilities.setSystemParameters(certificateAuthority);

        //Create Bob and Alice and receive their credentials
        System.out.println("Creating Bob (sender)...");
        Client Bob = new Client("bob@gmail.com");
        System.out.println("Issuing digital credential for Bob");
        Bob.requestCredential(certificateAuthority);

        System.out.println("Creating Alice (receiver)...");
        Client Alice = new Client("alice@gmail.com");
        System.out.println("Issuing digital credential for Alice");
        Alice.requestCredential(certificateAuthority);

        //Get blinded credentials
        System.out.println("Blinding Alice's Credentials...");
        Alice.blindCredentialX();
        Alice.blindCredentialY();

        //show and verify credentials
        Alice.showBlindedCredentialsToPKG(pkg);

        //after verification, pkg must compute blinded private key k'


        //Alice must unblind private key k' -> k
        //and use k to decrypt

        //Get private key and create cipher text, print out to prove it works Temporary method
//        PrivateKey privateKey = ibe.extract(Alice.getEmail());
//        CipherTextTuple c = Bob.sendMessage(Alice.getEmail(), ibe);
//
//        ibe.decrypt(privateKey, c).ifPresent(System.out::println);

    }
}
