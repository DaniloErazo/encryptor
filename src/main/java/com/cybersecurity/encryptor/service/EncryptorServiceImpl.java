package com.cybersecurity.encryptor.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

@Service
public class EncryptorServiceImpl implements EncryptorService {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int IV_LENGTH_BYTE = 16;
    private static final int SALT_LENGTH_BYTE = 16;
    private static final String FILES_DIR = "files";

    @Override
    public File encryptFile(MultipartFile file, String password) throws Exception {
        byte[] salt = generateSalt();
        byte[] key = generateKeyFromPassword(password, salt);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] iv = new byte[IV_LENGTH_BYTE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), ivSpec);


        byte[] inputBytes = file.getBytes();
        byte[] hash = computeSHA256(inputBytes);
        byte[] cipherText = cipher.doFinal(inputBytes);

        File encryptedFile = new File(FILES_DIR + "/encrypted_" + file.getOriginalFilename());
        try (FileOutputStream fos = new FileOutputStream(encryptedFile)) {
            fos.write(salt);
            fos.write(iv);
            fos.write(hash);
            fos.write(cipherText);
        }

        return encryptedFile;
    }

    @Override
    public File decryptFile(MultipartFile file, String password) throws Exception {
        byte[] fileContent = file.getBytes();

        byte[] salt = Arrays.copyOfRange(fileContent, 0, SALT_LENGTH_BYTE);
        byte[] iv = Arrays.copyOfRange(fileContent, SALT_LENGTH_BYTE, SALT_LENGTH_BYTE + IV_LENGTH_BYTE);
        byte[] storedHash = Arrays.copyOfRange(fileContent, SALT_LENGTH_BYTE + IV_LENGTH_BYTE, SALT_LENGTH_BYTE + IV_LENGTH_BYTE + 32);
        byte[] cipherText = Arrays.copyOfRange(fileContent, SALT_LENGTH_BYTE + IV_LENGTH_BYTE + 32, fileContent.length);

        byte[] key = generateKeyFromPassword(password, salt);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), ivSpec);

        byte[] decryptedText;
        try {
            decryptedText = cipher.doFinal(cipherText);
        } catch (Exception e) {
            throw new SecurityException("Could not decrypt the file, wrong password or corrupted file!");
        }

        byte[] computedHash = computeSHA256(decryptedText);
        if (!Arrays.equals(storedHash, computedHash)) {
            throw new SecurityException("Hash does not match, data integrity compromised!");
        }

        File decryptedFile = new File(FILES_DIR+"/decrypted_" + file.getOriginalFilename());
        try (FileOutputStream fos = new FileOutputStream(decryptedFile)) {
            fos.write(decryptedText);
        }

        return decryptedFile;
    }

    private byte[] generateKeyFromPassword(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }

    private byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    private byte[] computeSHA256(byte[] inputBytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(inputBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
