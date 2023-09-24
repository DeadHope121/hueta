package com.example.demo5;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;


public class HelloController {

    private static final String VIRUSTOTAL_API_KEY = "a6995f589bb2e0cf32c62d87d393b69ebd747a6a79fe69a69849d018516b3f7f";
    private static final String VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files";

    @FXML
    private Button addFile;

    @FXML
    private Text hi;

    @FXML
    void initialize() {
        addFile.setOnAction(event -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Select File");
            Stage stage = (Stage) addFile.getScene().getWindow();
            File selectedFile = fileChooser.showOpenDialog(stage);

            if (selectedFile != null) {
                try {
                    sendFileToVirusTotal(selectedFile);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });
    }

    private void sendFileToVirusTotal(File file) throws IOException {
        String boundary = Long.toHexString(System.currentTimeMillis());
        String CRLF = "\r\n";
        URL url = new URL(VIRUSTOTAL_API_URL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("x-apikey", VIRUSTOTAL_API_KEY);
        connection.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
        connection.setDoOutput(true);

        try (OutputStream os = connection.getOutputStream();
             PrintWriter writer = new PrintWriter(new OutputStreamWriter(os, "UTF-8"), true)) {

            writer.append("--" + boundary).append(CRLF);
            writer.append("Content-Disposition: form-data; name=\"file\"; filename=\"" + file.getName() + "\"").append(CRLF);
            writer.append("Content-Type: application/octet-stream").append(CRLF);
            writer.append(CRLF).flush();

            try (FileInputStream fileInputStream = new FileInputStream(file)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
                os.flush();
            }

            writer.append(CRLF).flush();
            writer.append("--" + boundary + "--").append(CRLF).flush();
        }

        int responseCode = connection.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                System.out.println("Response from VirusTotal: " + response.toString());

                // Parse the JSON response
                ObjectMapper objectMapper = new ObjectMapper();
                JsonNode rootNode = objectMapper.readTree(response.toString());

                // Extract the "id" field
                String id = rootNode.get("data").get("id").asText();
                System.out.println("File ID from VirusTotal: " + id);

                // You can use the 'id' for further processing.
            }
        } else {
            System.err.println("Failed to send the file to VirusTotal. HTTP Response Code: " + responseCode);
        }

        connection.disconnect();
    }

}