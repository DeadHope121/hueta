package com.example.demo5;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.layout.AnchorPane;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import java.util.Iterator;
import javafx.concurrent.Task;
import javafx.concurrent.WorkerStateEvent;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javafx.event.EventHandler;
import com.fasterxml.jackson.databind.JsonNode;

import com.fasterxml.jackson.databind.ObjectMapper;
import javafx.application.Platform;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;

public class HelloController {

    private static final String VIRUSTOTAL_API_KEY = "a6995f589bb2e0cf32c62d87d393b69ebd747a6a79fe69a69849d018516b3f7f";
    private static final String VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files";

    private static final String VIRUSTOTAL_API_URL2 = "https://www.virustotal.com/api/v3/analyses";

    @FXML
    private Button addFile;

    @FXML
    private Text ddda;

    @FXML
    private Button exit;

    @FXML
    private Button fl;

    @FXML
    private Text gim47;

    @FXML
    private Text gim472;

    @FXML
    private Text hi;

    @FXML
    private Text hi1;

    @FXML
    private AnchorPane hz;

    @FXML
    private Button program;

    @FXML
    private Button program1;

    @FXML
    private Text safe;

    @FXML
    private Button scan;

    @FXML
    private Text time;

    @FXML
    private Text unsafe;

    @FXML
    private Text virus;


    @FXML
    void initialize() {
        addFile.setOnAction(event -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Select File");
            Stage stage = (Stage) addFile.getScene().getWindow();
            File selectedFile = fileChooser.showOpenDialog(stage);
            ddda.setVisible(true);

            if (selectedFile != null) {
                // Reset the detected and undetected counters for each new file
                detectedCount = 0;
                undetectedCount = 0;

                // Create a new ScheduledExecutorService
                ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

                Task<String> sendFileTask = new Task<String>() {
                    @Override
                    protected String call() throws Exception {
                        return sendFileToVirusTotal(selectedFile);
                    }
                };

                sendFileTask.setOnSucceeded(new EventHandler<WorkerStateEvent>() {
                    @Override
                    public void handle(WorkerStateEvent event) {
                        String fileId = sendFileTask.getValue();
                        if (fileId != null) {
                            Runnable reportCheckTask = new Runnable() {
                                @Override
                                public void run() {
                                    try {
                                        if (detectedCount == 0 && undetectedCount == 0) {
                                            getFileReportFromVirusTotal(fileId);
                                        } else {
                                            // If there are detections, stop the periodic checks
                                            executor.shutdown();
                                        }
                                    } catch (IOException e) {
                                        e.printStackTrace();
                                    }
                                }
                            };

                            executor.scheduleAtFixedRate(reportCheckTask, 0, 2, TimeUnit.SECONDS);
                        }
                    }
                });


                new Thread(sendFileTask).start();
            }

        });
        gim47.setVisible(false);gim472.setVisible(false);ddda.setVisible(false);hz.setVisible(false);safe.setVisible(false);unsafe.setVisible(false);fl.setVisible(false);virus.setVisible(false);time.setVisible(false);
        exit.setOnAction(event -> {
            Platform.exit();

        });
        program1.setOnAction(event -> {
            addFile.setVisible(false);gim47.setVisible(false);gim472.setVisible(false);hi.setVisible(false);hi1.setVisible(false);hz.setVisible(false);safe.setVisible(false);unsafe.setVisible(false);addFile.setVisible(false);gim47.setVisible(false);gim472.setVisible(false);hi.setVisible(false);time.setVisible(true);virus.setVisible(true);// Hide the "addFile" button
        });
        program.setOnAction(event -> {
            addFile.setVisible(false);virus.setVisible(false);time.setVisible(false);gim47.setVisible(true);gim472.setVisible(true);hi.setVisible(false);hi1.setVisible(false);hz.setVisible(false);safe.setVisible(false);unsafe.setVisible(false);// Hide the "addFile" button
        });
        scan.setOnAction(event -> {addFile.setVisible(true);virus.setVisible(false);time.setVisible(false);gim47.setVisible(false);gim472.setVisible(false);hi.setVisible(true);// Show the "addFile" button
        });
        fl.setOnAction(event -> {
            fl.setVisible(false);safe.setVisible(false);virus.setVisible(false);time.setVisible(false);unsafe.setVisible(false);hi.setVisible(false);hi1.setVisible(false);hz.setVisible(false);addFile.setVisible(true);// Hide the "true"
        });
    }


    private String sendFileToVirusTotal(File file) throws IOException {
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

            try (BufferedInputStream fileInputStream = new BufferedInputStream(new FileInputStream(file))) {
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

                ObjectMapper objectMapper = new ObjectMapper();
                JsonNode rootNode = objectMapper.readTree(response.toString());

                String id = rootNode.get("data").get("id").asText();
                System.out.println("File ID from VirusTotal: " + id);

                return id;
            }
        } else {
            System.err.println("Failed to send the file to VirusTotal. HTTP Response Code: " + responseCode);
        }

        connection.disconnect();
        return null;
    }


    private int detectedCount = 0;
    private int undetectedCount = 0;

    private void getFileReportFromVirusTotal(String fileId) throws IOException {
        String reportUrl = VIRUSTOTAL_API_URL2 + "/" + fileId;

        URL url = new URL(reportUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("x-apikey", VIRUSTOTAL_API_KEY);

        int responseCode = connection.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }

                ObjectMapper objectMapper = new ObjectMapper();
                JsonNode rootNode = objectMapper.readTree(response.toString());

                JsonNode results = rootNode.get("data").get("attributes").get("results");

                Iterator<String> fieldNames = results.fieldNames();
                while (fieldNames.hasNext()) {
                    String antivirusName = fieldNames.next();
                    JsonNode antivirusResult = results.get(antivirusName);

                    String category = antivirusResult.get("category").asText();
                    System.out.println(antivirusName + " = " + category);

                    if ("malicious".equalsIgnoreCase(category)) {
                        detectedCount++;
                    } else {
                        undetectedCount++;
                    }
                }

                System.out.println("detected = " + detectedCount);
                System.out.println("undetected = " + undetectedCount);
                if ((detectedCount == 0) && (undetectedCount == 0)) {
                }
                else {
                    if (detectedCount > 5) {
                    unsafe.setVisible(true);fl.setVisible(true);
                    }
                    else {
                        safe.setVisible(true);fl.setVisible(true);
                    }
                    hz.setVisible(true);
                    addFile.setVisible(false);
                    ddda.setVisible(false);
                    hi.setText("Undetected: " + undetectedCount);
                    hi1.setText("Detected: " + detectedCount);
                }
            }
        } else {
            System.err.println("Failed to get the file report from VirusTotal. HTTP Response Code: " + responseCode);
        }

        connection.disconnect();
    }
}