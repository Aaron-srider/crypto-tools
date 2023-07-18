package fit.wenchao.crypto_tools;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/**
 * @author ccm
 */
public final class Sm2Util implements Sm2Constants {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final Sm2Signer SM2_SIGNER = Sm2Signer.INSTANCE;

    /**
     * 公钥加密
     *
     * @param input                 待加密数据
     * @param ecPublicKeyParameters 公钥参数
     * @param mode                  加密方式
     * @return 密文
     */
    public static byte[] encrypt(byte[] input, ECPublicKeyParameters ecPublicKeyParameters, SM2Engine.Mode mode) {
        SM2Engine engine = new SM2Engine(mode);
        ParametersWithRandom parametersWithRandom = new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom());
        engine.init(true, parametersWithRandom);
        try {
            return engine.processBlock(input, 0, input.length);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * sm2加密
     *
     * @param input 明文
     * @param publicKey 公钥
     * @return 密文
     */
    public static byte[] encrypt(byte[] input, byte[] publicKey) {
        ECPublicKeyParameters ecPublicKeyParameters = buildEcPublicKeyParameters(publicKey);
        return Sm2Cipher.to300Byte(Sm2Cipher.fromByte(encrypt(input, ecPublicKeyParameters, SM2Engine.Mode.C1C2C3)));
    }

    /**
     * 私钥解密
     *
     * @param input                  待解密数据
     * @param ecPrivateKeyParameters 私钥参数
     * @param mode                   加密方式
     * @return 明文
     */
    public static byte[] decrypt(byte[] input, ECPrivateKeyParameters ecPrivateKeyParameters, SM2Engine.Mode mode) {
        SM2Engine engine = new SM2Engine(mode);
        engine.init(false, ecPrivateKeyParameters);
        try {
            return engine.processBlock(input, 0, input.length);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] decrypt(byte[] cipher, byte[] privateKey) {
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(new BigInteger(1, privateKey),
                DOMAIN_PARAMS);
        return decrypt(Sm2Cipher.toByte(Sm2Cipher.from300Byte(cipher)), privateKeyParameters, SM2Engine.Mode.C1C2C3);
    }

    /**
     * 私钥签名
     *
     * @param input      待签名数据
     * @param privateKey 私钥
     * @return 返回Sm2Signature
     */
    public static Sm2Signature sign1(byte[] input, byte[] privateKey) {
        return Sm2Signature.fromDsa(signDsa(input, privateKey), StandardDSAEncoding.INSTANCE);
    }

    public static byte[] signDsa(byte[] input, byte[] privateKey) {
        return SM2_SIGNER.signDsa(input, privateKey);
    }

    static final int SIGN_LEN = 64;

    /**
     * 私钥签名
     *
     * @param input      待签名数据
     * @param privateKey 私钥
     * @return 返回rs_merge
     */
    public static byte[] sign(byte[] input, byte[] privateKey) {
        byte[] sign = Sm2Signature.toByte(sign1(input, privateKey));
        if (sign.length != SIGN_LEN) {
            sign = Sm2Signature.toByte(sign1(input, privateKey));
        }
        return sign;
    }

    /**
     * 签名验证
     *
     * @param input     原始数据
     * @param dsa       64字节纯签名
     * @param publicKey 64字节纯公钥
     * @return 成功
     */
    public static boolean verifyDsa(byte[] input, byte[] dsa, byte[] publicKey) {
        return SM2_SIGNER.verifyDsa(input, dsa, publicKey);
    }

    public static boolean verify(byte[] input, byte[] sign, byte[] publicKey) {
        return verifyDsa(input, Sm2Signature.byteToDsa(sign, StandardDSAEncoding.INSTANCE), publicKey);
    }

    /**
     * 生成公私钥
     *
     * @return 公私钥
     */
    public static Sm2KeyPair generateKeyPair() {
        SecureRandom random = new SecureRandom();
        ECKeyGenerationParameters keyGenerationParams = new ECKeyGenerationParameters(DOMAIN_PARAMS,
                random);
        ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
        keyGen.init(keyGenerationParams);
        AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();
        ECPublicKeyParameters ecPublicKeyParameters = (ECPublicKeyParameters) keyPair.getPublic();
        ECPrivateKeyParameters ecPrivateKeyParameters = (ECPrivateKeyParameters) keyPair.getPrivate();
        return new Sm2KeyPair(ecPublicKeyParameters.getQ().getAffineXCoord().getEncoded(), ecPublicKeyParameters.getQ().getAffineYCoord().getEncoded(), ecPrivateKeyParameters.getD().toByteArray());
    }

    public static PrivateKey privatekey(byte[] privateKey) throws Exception{
        ECPrivateKeyParameters ecPrivateKeyParameters = buildEcPrivateKeyParameters(privateKey);
        PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(ecPrivateKeyParameters);
        return BouncyCastleProvider.getPrivateKey(keyInfo);
    }
    /**
     * 构建私钥参数
     *
     * @param privateKey 私钥
     * @return 私钥参数
     */
    public static ECPrivateKeyParameters buildEcPrivateKeyParameters(byte[] privateKey) {
        return new ECPrivateKeyParameters(new BigInteger(1, privateKey),
                DOMAIN_PARAMS);
    }

    private static final int LENGTH = 32;

    public static ECPublicKeyParameters buildEcPublicKeyParameters(byte[] publicKey) {
        byte[] publicKeyX = Arrays.copyOf(publicKey, LENGTH);
        byte[] publicKeyY =  Arrays.copyOfRange(publicKey, LENGTH, publicKey.length);
        return new ECPublicKeyParameters(CURVE.createPoint(new BigInteger(1,
                publicKeyX), new BigInteger(1, publicKeyY)),
                DOMAIN_PARAMS);
    }


    private static final int C1_LEN = 65;
    private static final int C3_LEN = 32;

    public static byte[] changeC1C3C2ToAsn1(byte[] c1c3c2)  {
        byte[] c1 = Arrays.copyOfRange(c1c3c2, 0, C1_LEN);
        byte[] c3 = Arrays.copyOfRange(c1c3c2, C1_LEN, C1_LEN + C3_LEN);
        byte[] c2 = Arrays.copyOfRange(c1c3c2, C1_LEN + C3_LEN, c1c3c2.length);
        byte[] c1X = Arrays.copyOfRange(c1, 1, 33);
        byte[] c1Y = Arrays.copyOfRange(c1, 33, 65);

        BigInteger r = new BigInteger(1, c1X);
        BigInteger s = new BigInteger(1, c1Y);

        ASN1Integer x = new ASN1Integer(r);
        ASN1Integer y = new ASN1Integer(s);
        DEROctetString derDig = new DEROctetString(c3);
        DEROctetString derEnc = new DEROctetString(c2);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(x);
        v.add(y);
        v.add(derDig);
        v.add(derEnc);
        DERSequence seq = new DERSequence(v);
        try {
            return seq.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] pub(PublicKey publicKey){
        BCECPublicKey bcecPublicKey = (BCECPublicKey) publicKey;
        byte[] pub = bcecPublicKey.getQ().getEncoded(false);
        pub = Arrays.copyOfRange(pub,1,pub.length);
        return pub;
    }
}
