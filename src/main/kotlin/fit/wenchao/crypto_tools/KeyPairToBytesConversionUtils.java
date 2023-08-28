package fit.wenchao.crypto_tools;

import cn.hutool.core.util.ArrayUtil;
import cn.hutool.crypto.SmUtil;
import lombok.extern.slf4j.Slf4j;
import lombok.var;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Do the conversion between {@link KeyPair} and key bytes(row bytes or encoded)
 */
@Slf4j
public class KeyPairToBytesConversionUtils {

    private static final int Sm2KeyLength = 32;
    private static final SM2P256V1Curve CURVE = new SM2P256V1Curve();

    // region: private utils
    @NotNull
    private static ECPrivateKeyParameters buildEcPrivateKeyParameters(@NotNull byte[] privateKey) {
        return new ECPrivateKeyParameters(new BigInteger(1, privateKey),
                SmUtil.SM2_DOMAIN_PARAMS);
    }

    @NotNull
    private static ECPublicKeyParameters buildEcPublicKeyParameters(@NotNull byte[] publicKey) {
        byte[] publicKeyX = Arrays.copyOf(publicKey, Sm2KeyLength);
        byte[] publicKeyY = Arrays.copyOfRange(publicKey, Sm2KeyLength, publicKey.length);
        return new ECPublicKeyParameters(CURVE.createPoint(new BigInteger(1,
                publicKeyX), new BigInteger(1, publicKeyY)),
                SmUtil.SM2_DOMAIN_PARAMS);
    }
    // endregion


    // region: convert original bytes to KeyPair
    @NotNull
    public static PrivateKey rawBytesToPrivatekey(@NotNull byte[] rowPrivateKey) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            ECPrivateKeyParameters ecPrivateKeyParameters = buildEcPrivateKeyParameters(rowPrivateKey);
            PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(ecPrivateKeyParameters);
            var privateKey = BouncyCastleProvider.getPrivateKey(keyInfo);
            if(privateKey == null) {
                throw new RuntimeException();
            }
            return privateKey;
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert original key bytes to private key", e);
        }
    }


    /**
     * Convert original bytes of public key to {@link PublicKey} object
     *
     * @param rowPublicKey original bytes of public key
     * @return a {@link PublicKey} object
     */
    @NotNull
    public static PublicKey rawBytesToPublickey(@NotNull byte[] rowPublicKey) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            ECPublicKeyParameters ecPublicKeyParameters = buildEcPublicKeyParameters(rowPublicKey);
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ecPublicKeyParameters);
            PublicKey publicKey = BouncyCastleProvider.getPublicKey(subjectPublicKeyInfo);
            if(publicKey == null) {
                throw new RuntimeException();
            }
            return publicKey;
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert original key bytes to public key", e);
        }
    }
    // endregion


    // region: convert KeyPair to original bytes

    /**
     * Convert a {@link KeyPair} object to a {@link Sm2KeyPair} object. Frankly speaking, extract bytes from {@link KeyPair} object
     *
     * @param keyPair a {@link KeyPair} object
     * @return a {@link Sm2KeyPair} object with original bytes of public key and private key
     */
    @NotNull
    public static Sm2KeyPair convertKeyPairToSm2KeyPair(@NotNull KeyPair keyPair) {
        byte[] publicKeyBytes = KeyPairToBytesConversionUtils.publicKeyToBytes(keyPair.getPublic());
        byte[] privateKeyToBytes = KeyPairToBytesConversionUtils.privateKeyToBytes(keyPair.getPrivate());
        return new Sm2KeyPair(Arrays.copyOf(publicKeyBytes, 32), Arrays.copyOfRange(publicKeyBytes, 32, 64), privateKeyToBytes);
    }


    /**
     * Convert a {@link PrivateKey} object to original private key bytes
     *
     * @param privateKey a {@link PrivateKey} object
     * @return original private key bytes
     */
    @NotNull
    public static byte[] privateKeyToBytes(@NotNull PrivateKey privateKey) {
        BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) privateKey;

        byte[] extractPrivateKeyValue = bcecPrivateKey.getD().toByteArray();
        if (extractPrivateKeyValue.length == 33) {
            extractPrivateKeyValue = Arrays.copyOfRange(extractPrivateKeyValue, 1, 33);
        }
        log.debug("private key length: " + extractPrivateKeyValue.length);
        log.debug("private key value: " + Arrays.toString(extractPrivateKeyValue));
        return extractPrivateKeyValue;
    }

    /**
     * Convert a {@link PublicKey} object to original public key bytes
     *
     * @param publicKey a {@link PublicKey} object
     * @return original public key bytes, joined by x and y
     */
    @NotNull
    public static byte[] publicKeyToBytes(@NotNull PublicKey publicKey) {
        BCECPublicKey bcecPublicKey = (BCECPublicKey) publicKey;

        byte[] extractPublicXValue = bcecPublicKey.getQ().getAffineXCoord().getEncoded();
        byte[] extractPublicYValue = bcecPublicKey.getQ().getAffineYCoord().getEncoded();

        byte[] publicKeyXY = ArrayUtil.addAll(extractPublicXValue, extractPublicYValue);
        log.debug("public key length: " + publicKeyXY.length);
        log.debug("public key value: " + Arrays.toString(publicKeyXY));

        // concat x and y
        return publicKeyXY;
    }

    // endregion


    // region: convert ASN.1 encoded bytes to KeyPair

    /**
     * Convert ASN.1 encoded public key bytes to a {@link PublicKey} object
     *
     * @param bytes ASN.1 encoded public key bytes
     * @return a {@link PublicKey} object
     */
    @NotNull
    public static PublicKey asn1BytesToPublicKey(@NotNull byte[] bytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytes);
            return keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert asn.1 bytes to public key", e);
        }
    }

    /**
     * Convert ASN.1 encoded private key bytes to a {@link PrivateKey} object
     *
     * @param bytes ASN.1 encoded private key bytes
     * @return a {@link PrivateKey} object
     */
    @NotNull
    public static PrivateKey asn1BytesToPrivateKey(@NotNull byte[] bytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytes);
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert asn.1 bytes to private key", e);
        }
    }
    // endregion
}
