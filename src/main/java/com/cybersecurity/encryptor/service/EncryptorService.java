package com.cybersecurity.encryptor.service;

import org.springframework.web.multipart.MultipartFile;

import java.io.File;

public interface EncryptorService {

    File encryptFile(MultipartFile file, String password) throws Exception;

    File decryptFile(MultipartFile file, String password) throws Exception;


}
