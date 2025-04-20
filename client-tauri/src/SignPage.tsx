import React, { useState } from "react";
import toast from "react-hot-toast";
import { invoke } from "@tauri-apps/api/core";

const SignPage: React.FC = () => {
  const [secretContent, setSecretContent] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [usernames, setUsernames] = useState<string>("");
  const [signerUsername, setSignerUsername] = useState<string>("");
  const [message, setMessage] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setSecretContent(reader.result as string);
    reader.onerror = () => toast.error("Failed to read key file");
    reader.readAsText(file);
  };

  const handleSubmit = async () => {
    if (!signerUsername) return toast.error("Signer Keybase user ID required");
    if (!secretContent) return toast.error("Secret key file required");
    const names = usernames
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s);
    console.log("Keybase IDs:", names);
    if (!names.includes(signerUsername)) {
      return toast.error("Signer user ID must be included in Keybase IDs list");
    }
    if (names.length === 0)
      return toast.error("Enter at least one Keybase user ID");
    if (!message) return toast.error("Message cannot be empty");
    setLoading(true);
    try {
      const resp = await fetch(
        `http://localhost:8080/keys?names=${names.join(",")}`
      );
      if (!resp.ok) throw new Error("Failed to fetch public keys");
      const pubkeys = await resp.json();
      const signerIndex = names.indexOf(signerUsername);
      const sig = await invoke("ring_sign", {
        pubkeys,
        armoredSecret: secretContent,
        password: password || null,
        message,
        signerIndex,
      });
      console.log("Signature:", sig);
      const { v, xs } = sig as { v: string; xs: string[] };
      const postRes = await fetch("http://localhost:8080/signatures", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ v, xs, members: names, message }),
      });
      if (!postRes.ok) throw new Error("Failed to send signature");
      toast.success("Signature generated and sent");
    } catch (e: any) {
      toast.error(e.toString());
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block font-medium">Secret Key File</label>
        <input
          type="file"
          accept=".asc,.pem"
          onChange={handleFileChange}
          className="mt-1"
        />
      </div>
      <div>
        <label className="block font-medium">
          Keybase User IDs (comma separated)
        </label>
        <input
          value={usernames}
          onChange={(e) => setUsernames(e.target.value)}
          className="mt-1 w-full border rounded px-2 py-1"
        />
      </div>
      <div>
        <label className="block font-medium">Signer Keybase User ID</label>
        <input
          value={signerUsername}
          onChange={(e) => setSignerUsername(e.target.value)}
          className="mt-1 w-full border rounded px-2 py-1"
        />
      </div>
      <div>
        <label className="block font-medium">
          Secret Key Password (if any)
        </label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="mt-1 w-full border rounded px-2 py-1"
        />
      </div>
      <div>
        <label className="block font-medium">Message</label>
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          className="mt-1 w-full border rounded px-2 py-1"
          rows={4}
        />
      </div>
      <button
        onClick={handleSubmit}
        disabled={loading}
        className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 disabled:opacity-50"
      >
        {loading ? "Signing..." : "Generate Signature"}
      </button>
    </div>
  );
};

export default SignPage;
