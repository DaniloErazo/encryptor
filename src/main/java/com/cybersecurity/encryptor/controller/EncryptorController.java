package com.cybersecurity.encryptor.controller;

import com.cybersecurity.encryptor.service.EncryptorService;
import lombok.AllArgsConstructor;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

@RestController
@AllArgsConstructor
@CrossOrigin
@RequestMapping("/encryptor")
public class EncryptorController {

    final private EncryptorService encryptorService;

    @PostMapping("/encrypt")
    public ResponseEntity<Resource> encryptFile(MultipartFile file, String key) throws Exception {
        File encrypted = encryptorService.encryptFile(file, key);

        return getResourceResponseEntity(encrypted);
    }

    @PostMapping("/decrypt")
    public ResponseEntity<Resource> decryptFile(MultipartFile file, String key) throws Exception {
        File decrypted = encryptorService.decryptFile(file, key);
        return getResourceResponseEntity(decrypted);
    }

    private ResponseEntity<Resource> getResourceResponseEntity(File file) {
        InputStreamResource resource;
        try {
            resource = new InputStreamResource(new FileInputStream(file));
        } catch (FileNotFoundException e) {
            return ResponseEntity.status(500).body(null);
        }

        return ResponseEntity.ok()
                .contentLength(file.length())
                .contentType(org.springframework.http.MediaType.APPLICATION_OCTET_STREAM)
                .header("Content-Disposition", "attachment; filename=" + file.getName())
                .body(resource);
    }


}
