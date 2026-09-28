const crypto = require("crypto");

module.exports = (req, res) => {
  // Chỉ chấp nhận method POST
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  // Parse body an toàn
  let body = req.body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch (_) {
      body = {};
    }
  }
  const { deviceId, password } = body || {};

  // Mật khẩu admin (ưu tiên ENV ADMIN_PASSWORD, mặc định: Minhyang18@@)
  const adminPassword = process.env.ADMIN_PASSWORD || "Minhyang18@@";
  const rawPrivateKey = process.env.PRIVATE_KEY;

  // Kiểm tra mật khẩu admin
  if (password !== adminPassword) {
    return res.status(401).json({ error: "Sai mật khẩu admin" });
  }

  // Kiểm tra biến môi trường PRIVATE_KEY
  if (!rawPrivateKey) {
    console.error("LỖI: Chưa cấu hình PRIVATE_KEY trong Environment Variables của Vercel!");
    return res.status(500).json({ error: "Server chưa cấu hình PRIVATE_KEY trên Vercel" });
  }

  // Kiểm tra Device ID
  if (!deviceId || typeof deviceId !== "string" || !deviceId.trim()) {
    return res.status(400).json({ error: "Thiếu Device ID của thiết bị" });
  }

  try {
    const cleanDeviceId = deviceId.trim();
    const privateKey = rawPrivateKey.replace(/\\n/g, "\n");

    const signature = crypto.sign("sha256", Buffer.from(cleanDeviceId, "utf8"), {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    });

    return res.status(200).json({
      success: true,
      deviceId: cleanDeviceId,
      key: signature.toString("base64url"),
    });
  } catch (err) {
    console.error("Lỗi khi ký key:", err);
    return res.status(500).json({
      error: "Lỗi ký key: " + (err.message || "Sai định dạng Private Key"),
    });
  }
};
