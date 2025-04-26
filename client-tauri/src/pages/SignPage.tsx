import React, { useState, useCallback } from "react";
import toast from "react-hot-toast";
import { useDropzone } from "react-dropzone";
import { useSign } from "../hooks/useSign";
import UserRow from "../components/UserRow";
import { UserEntry } from "../types";

const SignPage: React.FC = () => {
  const [secretContent, setSecretContent] = useState<string>("");
  const [fileName, setFileName] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [users, setUsers] = useState<UserEntry[]>([
    { id: "", isSigner: false },
  ]);
  const [message, setMessage] = useState<string>("");
  const { mutate: sign, isPending: signing } = useSign();

  const onDrop = useCallback((accepted: File[]) => {
    if (!accepted.length) return;
    const file = accepted[0];
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = () => setSecretContent(reader.result as string);
    reader.onerror = () => toast.error("Failed to read key file");
    reader.readAsText(file);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: false,
  });

  const handleUserChange = (idx: number, val: string) =>
    setUsers((prev) => prev.map((u, i) => (i === idx ? { ...u, id: val } : u)));
  const handleSignerSelect = (idx: number) =>
    setUsers((prev) => prev.map((u, i) => ({ ...u, isSigner: i === idx })));
  const handleMove = (idx: number, dir: number) =>
    setUsers((prev) => {
      const arr = [...prev];
      const t = idx + dir;
      if (t < 0 || t >= arr.length) return prev;
      [arr[idx], arr[t]] = [arr[t], arr[idx]];
      return arr;
    });
  const handleRemove = (idx: number) =>
    setUsers((prev) => prev.filter((_, i) => i !== idx));
  const handleAdd = () =>
    setUsers((prev) => [...prev, { id: "", isSigner: false }]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const valid = users.filter((u) => u.id.trim()).map((u) => u.id);
    const signerIndex = users.findIndex((u) => u.isSigner);
    if (!secretContent) return toast.error("Secret key file required");
    if (!valid.length) return toast.error("Enter at least one Keybase user ID");
    if (signerIndex < 0) return toast.error("Select one signer");
    if (!message) return toast.error("Message cannot be empty");
    sign({
      users: valid,
      secretContent,
      password: password || null,
      message,
      signerIndex,
    });
  };

  return (
    <form onSubmit={handleSubmit} className="max-w-lg mx-auto p-4 space-y-6">
      {/* Secret Key File */}
      <div>
        <label className="block font-medium mb-1">Secret Key File</label>
        <div
          {...getRootProps()}
          className={`border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors ${
            isDragActive ? "border-blue-500 bg-blue-50" : "border-gray-300"
          }`}
        >
          <input {...getInputProps()} />
          {fileName ? (
            <p className="text-sm text-gray-700">Loaded: {fileName}</p>
          ) : isDragActive ? (
            <p className="text-blue-500">Drop the key file here...</p>
          ) : (
            <p className="text-gray-500">
              Drag & drop a key file here, or click to select
            </p>
          )}
        </div>
      </div>
      {/* User Entries */}
      <div className="space-y-2">
        <label className="block font-medium">Keybase User IDs</label>
        {users.map((u, i) => (
          <UserRow
            key={i}
            user={u}
            index={i}
            onChange={handleUserChange}
            onSignerSelect={handleSignerSelect}
            onMove={handleMove}
            onRemove={handleRemove}
            disableUp={i === 0}
            disableDown={i === users.length - 1}
            disableRemove={users.length === 1}
          />
        ))}
        <button
          type="button"
          onClick={handleAdd}
          className="mt-2 px-3 py-1 bg-blue-500 text-white rounded"
        >
          + Add
        </button>
      </div>
      {/* Password and Message */}
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
        type="submit"
        disabled={signing}
        className="w-full bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 disabled:opacity-50"
      >
        {signing ? "Signing..." : "Generate Signature"}
      </button>
    </form>
  );
};

export default SignPage;
