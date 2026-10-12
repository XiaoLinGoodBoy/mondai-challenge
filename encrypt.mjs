// index.html（問題集の本体）をパスワードで暗号化して docs/index.html を作る。
// 使い方：node encrypt.mjs
// パスワードは .password ファイル（GitHub には上げない）から読む。

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";

const ITERATIONS = 600000;

const password = readFileSync(new URL("./.password", import.meta.url), "utf8").trim();
const plain = readFileSync(new URL("./index.html", import.meta.url), "utf8");

// salt は固定にする（問題を更新しても，覚えたパスワードがそのまま使える）
const saltFile = new URL("./.salt", import.meta.url);
if (!existsSync(saltFile)) {
  writeFileSync(saltFile, Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("base64"));
}
const salt = new Uint8Array(Buffer.from(readFileSync(saltFile, "utf8").trim(), "base64"));
const iv = crypto.getRandomValues(new Uint8Array(12));
const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey(
  { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
  baseKey,
  { name: "AES-GCM", length: 256 },
  false,
  ["encrypt"]
);
const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plain)));

const b64 = (u8) => Buffer.from(u8).toString("base64");

const page = `<!doctype html>
<html lang="ja">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="robots" content="noindex, nofollow" />
<title>実力突破 問題チャレンジ</title>
<style>
  :root { --bg: #f5f7fa; --card: #ffffff; --text: #333333; --muted: #6b7280; --line: #dddddd; --accent: #4f6df5; --ng: #dc2626; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #15171c; --card: #1f2229; --text: #e6e6e6; --muted: #9aa1ad; --line: #3a3f4a; --accent: #8199ff; --ng: #f87171; color-scheme: dark; }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 16px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Hiragino Sans", "Yu Gothic UI", "Meiryo", sans-serif;
    background: var(--bg); color: var(--text);
  }
  form {
    width: 100%; max-width: 360px; background: var(--card); border-radius: 16px; padding: 28px 24px;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08); display: flex; flex-direction: column; gap: 14px;
  }
  h1 { margin: 0; font-size: 22px; text-align: center; }
  p { margin: 0; color: var(--muted); text-align: center; font-size: 14px; }
  input[type=password] {
    width: 100%; padding: 12px; font-size: 18px; border: 2px solid var(--line); border-radius: 10px;
    background: var(--card); color: var(--text); font-family: inherit;
  }
  input[type=password]:focus { outline: none; border-color: var(--accent); }
  label { display: flex; align-items: center; gap: 6px; font-size: 14px; color: var(--muted); }
  button {
    padding: 12px; border: none; border-radius: 10px; background: var(--accent); color: #fff;
    font-size: 17px; font-weight: bold; cursor: pointer; font-family: inherit;
  }
  button:disabled { opacity: 0.6; }
  .error { color: var(--ng); font-weight: bold; text-align: center; min-height: 1.4em; }
</style>
</head>
<body>
<form id="lock">
  <h1>📚 問題チャレンジ</h1>
  <p>パスワードを入れてください</p>
  <input type="password" id="pw" autocomplete="current-password" aria-label="パスワード" autofocus />
  <label><input type="checkbox" id="remember" checked />この端末で覚えておく</label>
  <button type="submit" id="go">ひらく</button>
  <div class="error" id="err"></div>
</form>
<script>
const DATA = { salt: "${b64(salt)}", iv: "${b64(iv)}", cipher: "${b64(cipher)}", iterations: ${ITERATIONS} };
const KEY_STORE = "mondai-challenge-key";
const u8 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function decryptWith(rawKey) {
  const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: u8(DATA.iv) }, key, u8(DATA.cipher));
  return new TextDecoder().decode(plain);
}

async function deriveRaw(password) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: u8(DATA.salt), iterations: DATA.iterations, hash: "SHA-256" }, base, 256);
  return new Uint8Array(bits);
}

function show(html) {
  document.open();
  document.write(html);
  document.close();
}

// 覚えている鍵があれば自動でひらく（問題を更新すると鍵が変わるので，そのときは一度だけ入れ直し）
(async () => {
  let saved = null;
  try { saved = localStorage.getItem(KEY_STORE + ":" + DATA.salt); } catch (e) {}
  if (!saved) return;
  try { show(await decryptWith(u8(saved))); } catch (e) {}
})();

document.getElementById("lock").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = document.getElementById("go");
  const err = document.getElementById("err");
  btn.disabled = true;
  err.textContent = "";
  try {
    const raw = await deriveRaw(document.getElementById("pw").value);
    const html = await decryptWith(raw);
    if (document.getElementById("remember").checked) {
      try {
        for (let i = localStorage.length - 1; i >= 0; i--) {
          const k = localStorage.key(i);
          if (k && k.startsWith(KEY_STORE + ":")) localStorage.removeItem(k);
        }
        localStorage.setItem(KEY_STORE + ":" + DATA.salt, btoa(String.fromCharCode(...raw)));
      } catch (e) {}
    }
    show(html);
  } catch (e) {
    err.textContent = "パスワードがちがいます";
    btn.disabled = false;
  }
});
</script>
</body>
</html>
`;

mkdirSync(new URL("./docs/", import.meta.url), { recursive: true });
writeFileSync(new URL("./docs/index.html", import.meta.url), page);
console.log("docs/index.html を作成しました");
