import React from "react";
import { UserEntry } from "../types";

type Props = {
  user: UserEntry;
  index: number;
  onChange: (idx: number, value: string) => void;
  onSignerSelect: (idx: number) => void;
  onMove: (idx: number, dir: number) => void;
  onRemove: (idx: number) => void;
  disableUp: boolean;
  disableDown: boolean;
  disableRemove: boolean;
};

const UserRow: React.FC<Props> = ({
  user,
  index,
  onChange,
  onSignerSelect,
  onMove,
  onRemove,
  disableUp,
  disableDown,
  disableRemove,
}) => (
  <div className="flex items-center gap-2">
    <input
      value={user.id}
      onChange={(e) => onChange(index, e.target.value)}
      disabled={user.isSigner}
      className={`flex-1 border rounded px-2 py-1 ${
        user.isSigner ? "bg-gray-300" : ""
      }`}
      placeholder="User ID"
    />
    <button
      type="button"
      onClick={() => onSignerSelect(index)}
      className="px-2 py-1 bg-green-500 text-white rounded"
      disabled={!user.id}
    >
      署名者
    </button>
    <button
      type="button"
      onClick={() => onMove(index, -1)}
      disabled={disableUp}
      className="px-2 py-1 bg-gray-300 text-white rounded disabled:opacity-50"
    >
      ↑
    </button>
    <button
      type="button"
      onClick={() => onMove(index, 1)}
      disabled={disableDown}
      className="px-2 py-1 bg-gray-300 text-white rounded disabled:opacity-50"
    >
      ↓
    </button>
    <button
      type="button"
      onClick={() => onRemove(index)}
      disabled={disableRemove}
      className="px-2 py-1 bg-red-500 text-white rounded disabled:opacity-50"
    >
      -
    </button>
  </div>
);

export default UserRow;
