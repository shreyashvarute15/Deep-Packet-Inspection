
import express from "express";
import cors from "cors";
import multer from "multer";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  mkdir,
  readFile,
  unlink,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;

const projectRoot = path.resolve(__dirname, "..");
const analyzerPath = process.env.ANALYZER_PATH || (process.platform === "win32" ? path.join(projectRoot, "build-ucrt64", "packet_analyzer.exe") : path.join(projectRoot, "packet_analyzer"));

const uploadDir = path.join(__dirname, "uploads");
const reportDir = path.join(__dirname, "reports");

await mkdir(uploadDir, { recursive: true });
await mkdir(reportDir, { recursive: true });

app.use(cors());

const upload = multer({
  dest: uploadDir,
  limits: {
    fileSize: 50 * 1024 * 1024,
    files: 1,
  },
  fileFilter: (_req, file, callback) => {
    const ext = path.extname(file.originalname).toLowerCase();

    if (![".pcap", ".cap"].includes(ext)) {
      return callback(new Error("Upload a .pcap or .cap file."));
    }

    callback(null, true);
  },
});

app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "DPI Analyzer API",
  });
});

app.post("/api/analyze", upload.single("pcap"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({
      error: "Upload a PCAP file using the 'pcap' field.",
    });
  }

  const reportPath = path.join(reportDir, `${randomUUID()}.json`);

  try {
    const report = await new Promise((resolve, reject) => {
      const child = spawn(
        analyzerPath,
        ["--pcap", req.file.path, "--output", reportPath],
        {
          cwd: projectRoot,
          shell: false,
          windowsHide: true,
        }
      );

      let stderr = "";
      let settled = false;

      const timeout = setTimeout(() => {
        child.kill();
        finish(new Error("Analysis timed out after 120 seconds."));
      }, 120_000);

      function finish(error, result) {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        if (error) reject(error);
        else resolve(result);
      }

      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString();
      });

      child.on("error", (error) => finish(error));

      child.on("close", async (code) => {
        if (code !== 0) {
          return finish(
            new Error(`Analyzer exited with code ${code}. ${stderr}`)
          );
        }

        try {
          const json = await readFile(reportPath, "utf8");
          finish(null, JSON.parse(json));
        } catch (error) {
          finish(new Error(`Could not read report: ${error.message}`));
        }
      });
    });

    res.json({
      success: true,
      filename: path.basename(req.file.originalname),
      report,
    });
  } catch (error) {
    console.error("Analysis failed:", error.message);
    res.status(500).json({
      error: "PCAP analysis failed.",
      details: error.message,
    });
  } finally {
    await Promise.all(
      [req.file.path, reportPath].map((file) =>
        unlink(file).catch(() => {})
      )
    );
  }
});

app.use((error, _req, res, _next) => {
  if (error instanceof multer.MulterError) {
    const status = error.code === "LIMIT_FILE_SIZE" ? 413 : 400;
    return res.status(status).json({
      error:
        status === 413
          ? "Maximum upload size is 50 MB."
          : error.message,
    });
  }

  res.status(400).json({
    error: error.message || "Invalid request.",
  });
});

app.listen(PORT, () => {
  console.log(`DPI API running at http://localhost:${PORT}`);
});

