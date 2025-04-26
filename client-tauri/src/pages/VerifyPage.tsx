import React, { useState } from "react";
import toast from "react-hot-toast";
import { useSignatures } from "../hooks/useSignatures";
import { useVerify } from "../hooks/useVerify";
import RecordCard from "../components/RecordCard";
import type { SignatureRecord } from "../types";

const VerifyPage: React.FC = () => {
  const [username, setUsername] = useState<string>("");
  const [verifying, setVerifying] = useState<Record<string, boolean>>({});
  const [results, setResults] = useState<Record<string, boolean | null>>({});

  const {
    data: records = [] as SignatureRecord[],
    isLoading: loadingRecords,
    refetch,
  } = useSignatures(username);

  const { verify } = useVerify();

  const handleFetch = (e: React.FormEvent) => {
    e.preventDefault();
    refetch();
  };

  const handleVerify = async (rec: SignatureRecord) => {
    setVerifying((p) => ({ ...p, [rec.id]: true }));
    try {
      const ok = await verify(rec);
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
          <RecordCard
            key={rec.id}
            rec={rec}
            verifying={verifying[rec.id]}
            result={results[rec.id] ?? null}
            onVerify={handleVerify}
          />
        ))}
        {records.length === 0 && !loadingRecords && (
          <div className="text-gray-500 text-center py-4">No signatures</div>
        )}
      </div>
    </form>
  );
};

export default VerifyPage;
