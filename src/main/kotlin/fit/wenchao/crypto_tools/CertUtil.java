package fit.wenchao.crypto_tools;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.date.DateField;
import cn.hutool.core.date.DateTime;
import cn.hutool.crypto.ECKeyUtil;
import cn.hutool.crypto.SmUtil;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

/**
 * @author ccm
 * @version V1.0
 * @Package com.ccm.sm.cert
 * @date 2020/8/27 2:00 下午
 */
public class CertUtil {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    /**
     * 解析标准证书（从二进制）
     *
     * @param certByte 证书
     * @return 解析后的证书
     */
    public static X509Certificate analysisCert(byte[] certByte) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X509","BC").generateCertificate(new ByteArrayInputStream(certByte));
        } catch (Exception e) {
            byte[] cert = Base64.decode(certByte);
            return analysisCert(cert);
        }
    }

    /**
     * 读取证书公钥,返回64字节公钥
     *
     * @param cert 证书
     * @return 公钥
     */
    private static byte[] getCertPk(X509Certificate cert) {
        try {
            SubjectPublicKeyInfo subjectPublicKeyInfo =
                    TBSCertificate.getInstance(cert.getTBSCertificate())
                            .getSubjectPublicKeyInfo();
            byte[] certPk =
                    subjectPublicKeyInfo.getPublicKeyData().getEncoded();
            return Arrays.copyOfRange(certPk, 4, certPk.length);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("无法从证书中获取公钥信息,请检查证书格式.");
        }
    }

    /**
     * 获取标准证书公钥信息
     *
     * @param cert 证书
     * @return 公钥
     */
    public static byte[] getX509CertPk(byte[] cert) {
        return getCertPk(analysisCert(cert));
    }

    /**
     * 生成证书
     * @param privateKey 私钥
     * @param publicKey 公钥
     * @param issuer 颁发者
     * @param subject 证书拥有者
     * @param sn 序列号
     * @return 证书
     */
    public static byte[] generateCert(byte[] privateKey, byte[] publicKey,
                                      String issuer, String subject, long sn) {
        try {
            X500Name issuerName = new X500Name(BCStyle.INSTANCE, issuer);
            X500Name subjectName = new X500Name(BCStyle.INSTANCE, subject);
            ECPublicKeyParameters param =
                    ECKeyUtil.toPublicParams(Arrays.copyOf(publicKey,32),
                            Arrays.copyOfRange(publicKey,32,64), SmUtil.SM2_DOMAIN_PARAMS);
            SubjectPublicKeyInfo keyInfo =
                    SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(param);
            Date begin = DateTime.now().toJdkDate();
            Date end = DateTime.now().offset(DateField.YEAR, 10).toJdkDate();
            X509v3CertificateBuilder builder =
                    new X509v3CertificateBuilder(issuerName,
                            new BigInteger(String.valueOf(sn)), begin, end,
                            subjectName, keyInfo);
            PrivateKey privateKeyInfo = Sm2Util.privatekey(privateKey);
            ContentSigner contentSigner = new JcaContentSignerBuilder(
                    "SM3WITHSM2").build(privateKeyInfo);
            builder.addExtension(Extension.keyUsage,
                    false,
                    new KeyUsage(KeyUsage.digitalSignature +
                            KeyUsage.nonRepudiation + KeyUsage.keyEncipherment + KeyUsage.keyAgreement));
            builder.addExtension(MiscObjectIdentifiers.netscapeCertComment,
                    false, new DERUTF8String("ccm"));
            builder.addExtension(Extension.basicConstraints, true,
                    new BasicConstraints(true));
            return builder.build(contentSigner).getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 生成证书,序列号为当前时间
     * @param privateKey 私钥
     * @param publicKey 公钥
     * @param issuer 颁发者
     * @param subject 证书拥有者
     * @return 证书
     */
    public static byte[] generateCert(byte[] privateKey, byte[] publicKey,
                                      String issuer, String subject) {
        return generateCert(privateKey, publicKey, issuer, subject, System.currentTimeMillis());
    }

    /**
     * 根据证书请求生成证书
     * @param request request
     * @param rootSk rootSk
     * @return cert
     */
    public static byte[] generateCertByRequest(byte[] request, byte[] rootSk) {
        try {
            PKCS10CertificationRequest cr = new PKCS10CertificationRequest(request);
            byte[] pubResultKey = new byte[64];
            byte[] pubKey = cr.getSubjectPublicKeyInfo().getPublicKeyData().getEncoded();
            System.arraycopy(pubKey, 4, pubResultKey, 0, 64);
            String subjectDN = cr.getSubject().toString();
            return generateCert(rootSk, pubResultKey, subjectDN, subjectDN);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
