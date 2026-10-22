<%@ page import="java.io.*,java.nio.file.*,java.util.*,jakarta.servlet.http.Part" %>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>

<%!
    private String escapeHtml(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;");
    }
%>

<%
    String message = "";

    if ("POST".equalsIgnoreCase(request.getMethod())) {
        try {
            Part uploadedFile = request.getPart("file");

            if (uploadedFile == null ||
                uploadedFile.getSize() == 0) {
                throw new Exception("Chưa chọn file.");
            }

            if (uploadedFile.getSize() > 5 * 1024 * 1024) {
                throw new Exception("File vượt quá 5 MB.");
            }

            String originalName =
                uploadedFile.getSubmittedFileName();

            if (originalName == null) {
                throw new Exception("Tên file không hợp lệ.");
            }

            originalName = originalName.replace("\\", "/");
            originalName = originalName.substring(
                originalName.lastIndexOf("/") + 1
            );


            Path uploadDir = Paths.get(
                "/var/lib/tomcat10/webapps/shopee/uploads"
            );

            Files.createDirectories(uploadDir);

            String extension = "";
            int dot = originalName.lastIndexOf(".");

            if (dot >= 0) {
                extension = originalName.substring(dot);
                extension = extension.replaceAll(
                    "[^a-zA-Z0-9.]", ""
                );
            }

            String storedName =
                UUID.randomUUID().toString() + extension;

            Path destination = uploadDir.resolve(storedName);

            try (InputStream input =
                     uploadedFile.getInputStream()) {
                Files.copy(input, destination);
            }

            message = "Upload thành công: " +
                      storedName;

        } catch (Exception e) {
            message = "Upload thất bại: " + e.getMessage();
        }
    }
%>

<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Vulnerable Upload Lab</title>

    <style>
        body {
            background: #f1f5f9;
            font-family: Arial, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 90vh;
        }

        .container {
            background: white;
            padding: 35px;
            width: 460px;
            border-radius: 12px;
            box-shadow: 0 5px 25px #0001;
        }

        h2 { color: #1e293b; }

        button {
            background: #2563eb;
            border: none;
            border-radius: 6px;
            padding: 12px 20px;
            color: white;
            cursor: pointer;
        }

        input { margin: 20px 0; }

        .notice {
            color: #64748b;
            font-size: 13px;
        }

        .result { color: #15803d; }
    </style>
</head>

<body>
<div class="container">

    <h2>Vulnerable File Upload Lab</h2>

    <p>Forensic & Compromise Detection PoC</p>

    <form method="POST"
          enctype="multipart/form-data">

        <input type="file" name="file" required>

        <button type="submit">
            Upload File
        </button>

    </form>

    <p class="result">
        <%= escapeHtml(message) %>
    </p>

    <p class="notice">
        Lab demonstration only.
    </p>

</div>
</body>
</html>

