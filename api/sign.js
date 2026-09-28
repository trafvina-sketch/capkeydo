const crypto = require("crypto");

// Khóa RSA Private Key mặc định khớp với Public Key trong app Android
const DEFAULT_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDcADPsmET3APBO
NEthxBU+Dz6jBvh0a+cwNyexcUwtmyYT08KbOHhuu4U3K/l7oDt+aGJy10ZJNGHu
mj3Q7quuqSJQiGiPmYj3bH6wcz5wgbgXl6GjZxRReE5/SwGLe56PKeXxcetT3MmP
XWTDgEfhUcoo93SQAAH/P16UVKDXaWc2NsxcSs/CGlodmrzskz3+AD8BEGwQspBJ
gFxFA51Gpt4WhbI32b+smF7JZG/sXvx/qtFXMkV5/HlwetFF8uaE7YBLa1Roky+U
7SdqU4jb+xHEW+zqw66B8xSoLt2HMKUrjWTsjWI7jPJ+PLneDuSscw3S0OBIBBMk
vpgC0vHzAgMBAAECggEAFWUpp5E5Z8IeHKTmTdg5bqMh5s3nPL8/qQc8I3wOugK0
Jcp6ywinYbF356EtrpGrJ4R0SpHYAoeHHKLAb0C+zoohTa6uaIS4dsOE4Jkckelz
o0u6Sv9b0P5/t85uFIgNqAOdmqkHB01aBsjA42hm1SlUnT5Phi+SAiZCBu/iAoDN
+Rgx7OurkjZNt1CWgzwiSNWd0SYC6lFvJ7QERL+slC3vDbA5vCptEXswa+8wmSL8
R+sgGEBYJyX/kplmj0ANlhHAkkWtG7aeoymkAfwtXUXLPoY+4ur5ntivzfk/GN2y
drYl9z51wY3VHSllbO1KD13g5Kp6auFaNIRUc37GzQKBgQD2cJt37ya8Fao+I9xY
lNYqk2Ib6tNYpQYtnI9x9kdLJ+a6GVHTsCloQFRoVIpYTmtsIApgFW+8o9vyC0wc
1zBEAjkgbQnRk/JhSRAYNlNjfgNAJhxPvKjVbM5cMoLgs8eQ1EyLzReLQHUF44Sa
2aHldPBvKkcU2VzV10nnW2NNPQKBgQDkiQd6DrnlxKnKflIM3hvthVURhgdAHMrz
/eOufUAiKtw1HXcM7S7BbPAek+A8hEgjL25Qd03Vy54UdJZY/OynxHac9e2yQFhU
7Cf2dKQM99GZksgK3iOptq4VUVbfUbOdaXv8ZKt7XGSOCHQEAzZPn5+wkhxMRXjS
6EFg/b6O7wKBgFMToQVsZIVxVEPAeQ6PliciKie5IOg4MX380kqbuGr4l4pS8MfJ
Ehxn20yUe1LLlOENaBH+B/3yyzmsX0s1q7qxeSqaN34kPshXBgrzfWcD2vqsHk0v
D0drd6GTEZXIZVVIjElwqSgzYX/LtC8zgKVGp6sB+JZptCcOfYZ1w2MNAoGBANq+
UjrBJ6xGniIk4NJSMjcZvQAF4qC6LoR2Clz0o9NQZPAuIMptp6gaZodOEX67OvT6
rEM2vniZ6dg4c8P/a2F1ifbY6kgIkMPQOrwKjw+ekK/HL9Q/JbGHGn9rGJSudhaA
Zd2CWiS8nb7ZVnqUvIJgDhCK+a0Dfg+ZoSJ+HcxfAoGBALpq0TS7p7gc6Z+t56CO
IqYujBU9ZU+AHM8iNrP3MA6sWC8oTn/gS3QWZ9JCzy2aWUJaVvxyD/zMcRqwZfZu
ipYwTj6P/4o6WTxo/gENDlxSPJ7s92LN9NwnpPB+rl85M8sErpIgq7nGgAmLSiio
NzdCPEp9ShZXdc3N+88963oL
-----END PRIVATE KEY-----`;

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

  // Mật khẩu admin (mặc định: Minhyang18@@)
  const adminPassword = process.env.ADMIN_PASSWORD || "Minhyang18@@";
  const rawPrivateKey = process.env.PRIVATE_KEY || DEFAULT_PRIVATE_KEY;

  // Kiểm tra mật khẩu admin
  if (password !== adminPassword) {
    return res.status(401).json({ error: "Sai mật khẩu admin" });
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
