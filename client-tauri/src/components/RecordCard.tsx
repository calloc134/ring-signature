import React from "react";
import { SignatureRecord } from "../types";

type Props = {
  rec: SignatureRecord;
  verifying: boolean;
  result: boolean | null;
  onVerify: (rec: SignatureRecord) => void;
};

const RecordCard: React.FC<Props> = ({ rec, verifying, result, onVerify }) => (
  <div className="flex flex-col border p-4 rounded gap-4">
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
          {result != null &&
            (result ? (
              <span className="text-green-500">✔︎</span>
            ) : (
              <span className="text-red-500">✗</span>
            ))}
          <button
            onClick={() => onVerify(rec)}
            disabled={verifying}
            className="bg-gray-500 text-white px-4 py-2 rounded disabled:opacity-50 text-sm"
          >
            {verifying ? "Verifying..." : "Verify"}
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
);

export default RecordCard;
