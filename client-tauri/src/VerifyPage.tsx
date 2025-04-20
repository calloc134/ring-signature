import React, { useState } from "react";
import toast from "react-hot-toast";
import { invoke } from "@tauri-apps/api/core";

interface SignatureRecord {
  id: string;
  message: string;
  v: string;
  xs: string[];
  members: string[];
  created_at: string;
}

const VerifyPage: React.FC = () => {
  const [username, setUsername] = useState<string>("");
  // message is provided by each signature record
  const [records, setRecords] = useState<SignatureRecord[]>([]);
  const [loadingRecords, setLoadingRecords] = useState<boolean>(false);
  const [verifying, setVerifying] = useState<Record<string, boolean>>({});
  const [results, setResults] = useState<Record<string, boolean | null>>({});

  const handleFetch = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!username) return toast.error("Enter Keybase user ID");
    setLoadingRecords(true);
    setRecords([]);
    try {
      const resp = await fetch(`http://localhost:8080/signatures/${username}`);
      if (!resp.ok) throw new Error("Failed to fetch signatures");
      const data: SignatureRecord[] = await resp.json();
      setRecords(data);
    } catch (e: any) {
      toast.error(e.toString());
    } finally {
      setLoadingRecords(false);
    }
  };

  const handleVerify = async (rec: SignatureRecord) => {
    setVerifying((prev) => ({ ...prev, [rec.id]: true }));
    try {
      const resp = await fetch(
        `http://localhost:8080/keys?names=${rec.members.join(",")}`
      );
      if (!resp.ok) throw new Error("Failed to fetch public keys");
      const pubkeys = await resp.json();
      const ok = await invoke("ring_verify", {
        pubkeys,
        signature: { v: rec.v, xs: rec.xs },
        message: rec.message,
      });
      const verified = ok as boolean;
      setResults((prev) => ({ ...prev, [rec.id]: verified }));
      verified
        ? toast.success("Signature valid")
        : toast.error("Signature invalid");
    } catch (e: any) {
      toast.error(e.toString());
    } finally {
      setVerifying((prev) => ({ ...prev, [rec.id]: false }));
    }
  };

  return (
    <form onSubmit={handleFetch} className="space-y-4">
      <div className="flex flex-col sm:flex-row gap-2 items-center">
        <input
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Keybase User ID"
          className="flex-1 border rounded px-4 py-2"
        />
        <button
          type="submit"
          disabled={loadingRecords}
          className="bg-blue-500 text-white px-4 py-2 rounded disabled:opacity-50"
        >
          {loadingRecords ? "Loading..." : "Fetch Signatures"}
        </button>
      </div>
      <div className="space-y-2 max-h-[60vh] overflow-auto">
        {records.map((rec) => (
          <div
            key={rec.id}
            className="flex flex-col sm:flex-row justify-between items-start sm:items-center border p-4 rounded gap-4"
          >
            <div className="flex-1 min-w-0 overflow-x-auto">
              <p className="text-sm font-medium break-words">{rec.message}</p>
            </div>
            <div className="flex flex-col text-xs text-gray-500 text-right min-w-[120px]">
              <span className="text-gray-700">v: {rec.v.slice(0, 10)}...</span>
              <span>{new Date(rec.created_at).toLocaleString()}</span>
            </div>
            <div className="flex items-center gap-2">
              {results[rec.id] != null &&
                (results[rec.id] ? (
                  <span className="text-green-500">✔︎</span>
                ) : (
                  <span className="text-red-500">✗</span>
                ))}
              <button
                onClick={() => handleVerify(rec)}
                disabled={verifying[rec.id]}
                className="bg-gray-500 text-white px-4 py-2 rounded disabled:opacity-50"
              >
                {verifying[rec.id] ? "Verifying..." : "Verify"}
              </button>
            </div>
          </div>
        ))}
        {records.length === 0 && !loadingRecords && (
          <div className="text-gray-500 text-center py-4">No signatures</div>
        )}
      </div>
    </form>
  );
};

export default VerifyPage;
