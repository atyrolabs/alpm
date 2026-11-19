"use strict";

const crypto = require("crypto");
const axios = require("axios");

const DISCORD_API_BASE = "https://discord.com/api/v10";

/**
 * Helper to fetch current Discord configuration from process.env
 */
function getDiscordConfig() {
  return {
    botToken: (process.env.DISCORD_BOT_TOKEN || "").trim(),
    clientId: (process.env.DISCORD_CLIENT_ID || "").trim(),
    clientSecret: (process.env.DISCORD_CLIENT_SECRET || "").trim(),
    redirectUri: (process.env.DISCORD_REDIRECT_URI || "http://localhost:3000/api/auth/discord/callback").trim(),
    enabled: (process.env.DISCORD_2FA_ENABLED || "true").toLowerCase() !== "false"
  };
}

/**
 * Generate a cryptographically secure 6-digit numeric OTP code
 */
function generateOtpCode() {
  const codeInt = crypto.randomInt(100000, 1000000);
  return codeInt.toString();
}

/**
 * Hash an OTP code using HMAC-SHA256 with the server encryption key
 */
function hashOtpCode(code) {
  const secret = process.env.ENCRYPTION_KEY || process.env.SESSION_SECRET || "alpm_2fa_secure_key_fallback";
  return crypto.createHmac("sha256", secret).update(String(code).trim()).digest("hex");
}

/**
 * Timing-safe comparison of provided OTP with stored HMAC hash
 */
function verifyOtpCode(inputCode, storedHash) {
  if (!inputCode || !storedHash) return false;
  try {
    const inputHash = hashOtpCode(inputCode);
    const bufA = Buffer.from(inputHash, "utf8");
    const bufB = Buffer.from(storedHash, "utf8");
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  } catch (err) {
    console.error("[2FA] Error in verifyOtpCode:", err);
    return false;
  }
}

/**
 * Generate 10 cryptographically random, formatted backup recovery codes
 * Format: XXXX-XXXX-XXXX
 */
function generateBackupCodes(count = 10) {
  const chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"; // 32 characters, no ambiguous 0/O or 1/I
  const codes = [];
  for (let i = 0; i < count; i++) {
    let part1 = "";
    let part2 = "";
    let part3 = "";
    for (let j = 0; j < 4; j++) part1 += chars[crypto.randomInt(0, chars.length)];
    for (let j = 0; j < 4; j++) part2 += chars[crypto.randomInt(0, chars.length)];
    for (let j = 0; j < 4; j++) part3 += chars[crypto.randomInt(0, chars.length)];
    codes.push(`${part1}-${part2}-${part3}`);
  }
  return codes;
}

/**
 * Normalize and hash a single backup recovery code
 */
function hashBackupCode(code, userUuid = "") {
  const normalized = String(code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  const secret = process.env.ENCRYPTION_KEY || process.env.SESSION_SECRET || "alpm_backup_code_secret";
  return crypto.createHmac("sha256", secret).update(`${normalized}:${userUuid}`).digest("hex");
}

/**
 * Verify an input code against an array of stored hashed backup codes.
 * If valid, consumes and removes that single-use code from the array.
 */
function verifyAndConsumeBackupCode(rawInputCode, storedHashedCodesArray = [], userUuid = "") {
  const normalized = String(rawInputCode || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (normalized.length < 8) return { valid: false };

  const inputHash = hashBackupCode(normalized, userUuid);
  const inputBuf = Buffer.from(inputHash, "utf8");

  let matchIndex = -1;
  for (let i = 0; i < storedHashedCodesArray.length; i++) {
    const candidateHash = storedHashedCodesArray[i];
    const candidateBuf = Buffer.from(candidateHash, "utf8");
    if (candidateBuf.length === inputBuf.length && crypto.timingSafeEqual(candidateBuf, inputBuf)) {
      matchIndex = i;
      break;
    }
  }

  if (matchIndex >= 0) {
    const remainingCodes = [...storedHashedCodesArray];
    remainingCodes.splice(matchIndex, 1);
    return { valid: true, remainingCodes, burnedCodeHash: storedHashedCodesArray[matchIndex] };
  }

  return { valid: false };
}

/**
 * Send 6-digit OTP code to user's Discord account via DM
 */
async function sendDiscordOtp(discordUserId, otpCode, options = {}) {
  const config = getDiscordConfig();
  const purpose = options.purpose || "login";
  const username = options.username || "User";
  const ip = options.ip || "Unknown IP";

  const purposeLabels = {
    login: "Panel Sign-In Verification",
    forgot_password: "Password Reset Request",
    setup_2fa: "Two-Factor Authentication Setup",
    admin_action: "Administrative Security Verification"
  };

  const actionName = purposeLabels[purpose] || "Security Verification";

  // If bot token is not configured or in development simulation
  if (!config.botToken || config.botToken.length < 20 || config.botToken.includes("YOUR_BOT_TOKEN")) {
    console.log(`\n=============================================================`);
    console.log(`[DISCORD 2FA SIMULATION MODE]`);
    console.log(`Recipient Discord ID: ${discordUserId}`);
    console.log(`Purpose             : ${actionName}`);
    console.log(`6-Digit OTP Code    : >>> ${otpCode} <<<`);
    console.log(`Expires In          : 5 minutes`);
    console.log(`Client IP           : ${ip}`);
    console.log(`(Configure DISCORD_BOT_TOKEN in .env to deliver real Discord DMs)`);
    console.log(`=============================================================\n`);
    return {
      success: true,
      simulated: true,
      message: "Simulation mode: verification code generated and logged to panel server console."
    };
  }

  try {
    // Step 1: Open direct message (DM) channel with the user
    const channelRes = await axios.post(
      `${DISCORD_API_BASE}/users/@me/channels`,
      { recipient_id: String(discordUserId).trim() },
      {
        headers: {
          Authorization: `Bot ${config.botToken}`,
          "Content-Type": "application/json"
        },
        timeout: 8000
      }
    );

    const channelId = channelRes.data?.id;
    if (!channelId) {
      throw new Error("Failed to open Discord direct message channel with user.");
    }

    // Step 2: Construct security embed message
    const embed = {
      title: "🔐 ALPM Security Verification Code",
      color: 0x5865F2, // Discord Blurple
      description: `Hello **${username}**,\n\nUse the single-use 6-digit verification code below to complete your **${actionName}**.\n\n# \`\`\`${otpCode}\`\`\`\n\n> ⏱️ **This code expires in 5 minutes.**`,
      fields: [
        {
          name: "Action",
          value: actionName,
          inline: true
        },
        {
          name: "Requested From",
          value: `\`${ip}\``,
          inline: true
        },
        {
          name: "Expires In",
          value: "5 Minutes",
          inline: true
        }
      ],
      footer: {
        text: "Never share this code with anyone. ALPM Staff will never ask for your verification code."
      },
      timestamp: new Date().toISOString()
    };

    // Step 3: Send message into DM channel
    await axios.post(
      `${DISCORD_API_BASE}/channels/${channelId}/messages`,
      { embeds: [embed] },
      {
        headers: {
          Authorization: `Bot ${config.botToken}`,
          "Content-Type": "application/json"
        },
        timeout: 8000
      }
    );

    return {
      success: true,
      simulated: false,
      channelId
    };
  } catch (error) {
    console.error(`[DISCORD 2FA ERROR] Failed to send OTP to Discord user ${discordUserId}:`, error.response?.data || error.message);
    const discordErrorCode = error.response?.data?.code;
    let friendlyMessage = "Failed to deliver verification code through Discord.";

    if (discordErrorCode === 50007) {
      friendlyMessage = "Cannot send Discord DM to this account. Please verify that your Discord Privacy Settings allow Direct Messages from server members, and ensure you share at least one Discord server with our bot.";
    } else if (discordErrorCode === 10013) {
      friendlyMessage = "The linked Discord user account was not found. Please re-link your Discord account in settings.";
    } else if (error.response?.status === 401) {
      friendlyMessage = "Discord Bot Token is invalid or unauthorized. Please verify DISCORD_BOT_TOKEN in .env.";
    } else if (error.code === "ECONNABORTED" || error.code === "ETIMEDOUT") {
      friendlyMessage = "Connection to Discord API timed out. Please try again shortly.";
    }

    const err = new Error(friendlyMessage);
    err.original = error.response?.data || error.message;
    err.discordCode = discordErrorCode;
    throw err;
  }
}

/**
 * Generate Discord OAuth2 Authorization URL
 */
function getDiscordOAuthUrl(state) {
  const config = getDiscordConfig();
  if (!config.clientId) {
    throw new Error("DISCORD_CLIENT_ID is not configured in .env");
  }
  const redirectUri = encodeURIComponent(config.redirectUri);
  const encodedState = encodeURIComponent(state);
  return `https://discord.com/api/oauth2/authorize?client_id=${config.clientId}&redirect_uri=${redirectUri}&response_type=code&scope=identify%20email&state=${encodedState}&prompt=consent`;
}

/**
 * Exchange Discord OAuth2 Code for Access Token and User Profile
 */
async function exchangeDiscordCode(code) {
  const config = getDiscordConfig();
  if (!config.clientId || !config.clientSecret) {
    throw new Error("DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET must be configured in .env for OAuth2 linking.");
  }

  const params = new URLSearchParams();
  params.append("client_id", config.clientId);
  params.append("client_secret", config.clientSecret);
  params.append("grant_type", "authorization_code");
  params.append("code", code);
  params.append("redirect_uri", config.redirectUri);

  const tokenRes = await axios.post("https://discord.com/api/oauth2/token", params.toString(), {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 10000
  });

  const accessToken = tokenRes.data?.access_token;
  if (!accessToken) {
    throw new Error("Failed to obtain Discord OAuth2 access token.");
  }

  // Fetch user profile from Discord
  const userRes = await axios.get(`${DISCORD_API_BASE}/users/@me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    timeout: 10000
  });

  const u = userRes.data;
  let avatarUrl = "";
  if (u.avatar) {
    const ext = u.avatar.startsWith("a_") ? "gif" : "png";
    avatarUrl = `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.${ext}?size=256`;
  }

  return {
    id: u.id,
    username: u.username,
    discriminator: u.discriminator,
    globalName: u.global_name || u.username,
    avatar: avatarUrl,
    avatarHash: u.avatar || null,
    email: u.email || null,
    verified: !!u.verified
  };
}

/**
 * Query live Discord Bot status
 */
async function getDiscordBotStatus() {
  const config = getDiscordConfig();
  if (!config.botToken || config.botToken.length < 20 || config.botToken.includes("YOUR_BOT_TOKEN")) {
    return {
      configured: false,
      online: false,
      status: "unconfigured",
      message: "DISCORD_BOT_TOKEN is not configured in .env.",
      clientId: config.clientId ? `${config.clientId.slice(0, 6)}...` : "Not set",
      redirectUri: config.redirectUri,
      twoFactorEnabled: config.enabled
    };
  }

  try {
    const res = await axios.get(`${DISCORD_API_BASE}/users/@me`, {
      headers: { Authorization: `Bot ${config.botToken}` },
      timeout: 6000
    });

    const bot = res.data;
    let botAvatar = "";
    if (bot.avatar) {
      botAvatar = `https://cdn.discordapp.com/avatars/${bot.id}/${bot.avatar}.png?size=128`;
    }

    return {
      configured: true,
      online: true,
      status: "online",
      bot: {
        id: bot.id,
        username: bot.username,
        discriminator: bot.discriminator,
        avatar: botAvatar,
        tag: `${bot.username}#${bot.discriminator}`
      },
      clientId: config.clientId ? `${config.clientId.slice(0, 6)}...` : "Not set",
      redirectUri: config.redirectUri,
      twoFactorEnabled: config.enabled
    };
  } catch (err) {
    return {
      configured: true,
      online: false,
      status: "error",
      message: err.response?.data?.message || err.message,
      httpStatus: err.response?.status,
      clientId: config.clientId ? `${config.clientId.slice(0, 6)}...` : "Not set",
      redirectUri: config.redirectUri,
      twoFactorEnabled: config.enabled
    };
  }
}

module.exports = {
  getDiscordConfig,
  generateOtpCode,
  hashOtpCode,
  verifyOtpCode,
  generateBackupCodes,
  hashBackupCode,
  verifyAndConsumeBackupCode,
  sendDiscordOtp,
  getDiscordOAuthUrl,
  exchangeDiscordCode,
  getDiscordBotStatus
};
