import React, { useState } from "react";
import toast from "react-hot-toast";
import { invoke } from "@tauri-apps/api/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchJson } from "./api";

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
  const [verifying, setVerifying] = useState<Record<string, boolean>>({});
  const [results, setResults] = useState<Record<string, boolean | null>>({});

  // fetch signatures on demand
  const {
    data: records = [],
    isLoading: loadingRecords,
    refetch,
  } = useQuery<SignatureRecord[], Error>({
    queryKey: ["signatures", username],
    queryFn: () => fetchJson<SignatureRecord[]>(`/signatures/${username}`),
    enabled: false,
  });

  const queryClient = useQueryClient();

  const handleFetch = (e: React.FormEvent) => {
    e.preventDefault();
    refetch();
  };

  const handleVerify = async (rec: SignatureRecord) => {
    setVerifying((p) => ({ ...p, [rec.id]: true }));
    try {
      const keyKey = rec.members.join(",");
      const pubkeys = await queryClient.fetchQuery<string[]>({
        queryKey: ["pubkeys", keyKey],
        queryFn: () => fetchJson<string[]>(`/keys?names=${keyKey}`),
      });
      const ok = (await invoke("ring_verify", {
        pubkeys,
        signature: { v: rec.v, xs: rec.xs },
        message: rec.message,
      })) as boolean;
      setResults((p) => ({ ...p, [rec.id]: ok }));
      ok ? toast.success("Signature valid") : toast.error("Signature invalid");
    } catch (e: any) {
      toast.error(e.toString());
    } finally {
      setVerifying((p) => ({ ...p, [rec.id]: false }));
    }
  };

  return (
    <form onSubmit={handleFetch} className="space-y-4">
      <div className="flex flex-row  gap-2 items-center">
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
          <div key={rec.id} className="flex flex-col border p-4 rounded gap-4">
            <div className="flex justify-between items-start gap-4">
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium break-words">{rec.message}</p>
              </div>
              <div className="flex flex-col items-end gap-2 min-w-[320px]">
                <div className="text-xs text-gray-500 text-right">
                  <span className="text-gray-700 block">
                    v: {rec.v.slice(0, 30)}...
                  </span>
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
                    className="bg-gray-500 text-white px-4 py-2 rounded disabled:opacity-50 text-sm"
                  >
                    {verifying[rec.id] ? "Verifying..." : "Verify"}
                  </button>
                </div>
              </div>
            </div>
            <div className="mt-2 pt-2 border-t border-gray-200">
              <p className="text-xs text-gray-600 mb-1">Members:</p>
              <div className="flex flex-wrap gap-1">
                {rec.members.map((member) => (
                  <span
                    key={member}
                    className="text-xs bg-gray-100 text-gray-700 px-2 py-0.5 rounded"
                  >
                    {member}
                  </span>
                ))}
              </div>
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
