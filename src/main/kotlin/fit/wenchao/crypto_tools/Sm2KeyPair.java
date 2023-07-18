package fit.wenchao.crypto_tools;

import lombok.NoArgsConstructor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.io.Serializable;
import java.security.Security;
import java.util.Arrays;

/**
 * @author ccm
 */

@NoArgsConstructor
public class Sm2KeyPair implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 1039767320320404566L;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final int LENGTH = 32;

    private byte[] publicKeyX;
    private byte[] publicKeyY;
    private byte[] privateKey;


    public byte[] getPublicKeyX() {
        return publicKeyX;
    }

    public void setPublicKeyX(byte[] publicKeyX) {
        this.publicKeyX = publicKeyX;
    }

    public byte[] getPublicKeyY() {
        return publicKeyY;
    }

    public void setPublicKeyY(byte[] publicKeyY) {
        this.publicKeyY = publicKeyY;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
    }

    public Sm2KeyPair(byte[] publicKeyX, byte[] publicKeyY, byte[] privateKey) {
        this.publicKeyX = publicKeyX.length > LENGTH ?
                Arrays.copyOfRange(publicKeyX, 1, publicKeyX.length) :
                publicKeyX;
        this.publicKeyY = publicKeyY.length > LENGTH ?
                Arrays.copyOfRange(publicKeyY, 1, publicKeyY.length) :
                publicKeyY;
        this.privateKey = privateKey.length > LENGTH ?
                Arrays.copyOfRange(privateKey, 1, privateKey.length) :
                privateKey;
    }

    public byte[] getPublicKey() {
        return ByteUtils.concatenate(publicKeyX, publicKeyY);
    }


}
