import React, { useState, useCallback } from "react";
import toast from "react-hot-toast";
import { invoke } from "@tauri-apps/api/core";
import { useDropzone } from "react-dropzone";
import { useMutation } from "@tanstack/react-query";

// variables for mutation
interface SignatureVariables {
  users: string[];
  secretContent: string;
  password: string | null;
  message: string;
  signerIndex: number;
}
interface SignatureResult {
  v: string;
  xs: string[];
}

const SignPage: React.FC = () => {
  const [secretContent, setSecretContent] = useState<string>("");
  const [fileName, setFileName] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [users, setUsers] = useState<{ id: string; isSigner: boolean }[]>([
    { id: "", isSigner: false },
  ]);
  const [message, setMessage] = useState<string>("");

  const onDrop = useCallback((acceptedFiles: File[]) => {
    if (acceptedFiles.length === 0) return;
    const file = acceptedFiles[0];
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

  const handleUserChange = (index: number, value: string) => {
    const newUsers = [...users];
    newUsers[index].id = value;
    setUsers(newUsers);
  };

  const handleAddUser = () =>
    setUsers((prev) => [...prev, { id: "", isSigner: false }]);

  const handleRemoveUser = (index: number) => {
    setUsers((prev) => prev.filter((_, i) => i !== index));
  };

  const handleSignerSelect = (index: number) => {
    setUsers((prev) => prev.map((u, i) => ({ ...u, isSigner: i === index })));
  };

  const handleMoveUser = (index: number, direction: number) => {
    setUsers((prev) => {
      const newUsers = [...prev];
      const targetIndex = index + direction;
      if (targetIndex < 0 || targetIndex >= prev.length) return prev;
      [newUsers[index], newUsers[targetIndex]] = [
        newUsers[targetIndex],
        newUsers[index],
      ];
      return newUsers;
    });
  };

  const signMutation = useMutation<SignatureResult, Error, SignatureVariables>({
    mutationFn: async ({
      users,
      secretContent,
      password,
      message,
      signerIndex,
    }) => {
      // fetch pubkeys
      const resp = await fetch(
        `http://localhost:8080/keys?names=${users.join(",")}`
      );
      if (!resp.ok) throw new Error("Failed to fetch public keys");
      const pubkeys = await resp.json();

      // ring sign
      const sig = (await invoke("ring_sign", {
        pubkeys,
        armoredSecret: secretContent,
        password,
        message,
        signerIndex,
      })) as { v: string; xs: string[] };

      // post signature
      const postRes = await fetch("http://localhost:8080/signatures", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          v: sig.v,
          xs: sig.xs,
          members: users,
          message,
        }),
      });
      if (!postRes.ok) throw new Error("Failed to send signature");
      return sig;
    },
    onSuccess: () => {
      toast.success("Signature generated and sent");
    },
    onError: (err) => {
      toast.error(err.message);
    },
  });

  const handleSubmit = (e?: React.FormEvent) => {
    e?.preventDefault();
    const validUsers = users.filter((u) => u.id.trim()).map((u) => u.id);
    const signerIndex = validUsers.findIndex((_, i) => users[i].isSigner);
    if (!secretContent) return toast.error("Secret key file required");
    if (validUsers.length === 0)
      return toast.error("Enter at least one Keybase user ID");
    if (signerIndex < 0) return toast.error("Select one signer");
    if (!message) return toast.error("Message cannot be empty");

    signMutation.mutate({
      users: validUsers,
      secretContent,
      password: password || null,
      message,
      signerIndex,
    });
  };

  return (
    <form onSubmit={handleSubmit} className="max-w-lg mx-auto p-4 space-y-6">
      <div className="space-y-4">
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
        <div className="space-y-2">
          <label className="block font-medium">Keybase User IDs</label>
          {users.map((u, i) => (
            <div key={i} className="flex items-center gap-2">
              <input
                value={u.id}
                onChange={(e) => handleUserChange(i, e.target.value)}
                disabled={u.isSigner}
                className={`flex-1 border rounded px-2 py-1 ${
                  u.isSigner ? "bg-gray-100" : ""
                }`}
                placeholder="User ID"
              />
              <button
                type="button"
                onClick={() => handleSignerSelect(i)}
                className="px-2 py-1 bg-green-500 text-white rounded"
                disabled={!u.id}
              >
                署名者
              </button>
              <button
                type="button"
                onClick={() => handleMoveUser(i, -1)}
                disabled={i === 0}
                className="px-2 py-1 bg-gray-300 text-white rounded"
              >
                ↑
              </button>
              <button
                type="button"
                onClick={() => handleMoveUser(i, 1)}
                disabled={i === users.length - 1}
                className="px-2 py-1 bg-gray-300 text-white rounded"
              >
                ↓
              </button>
              <button
                type="button"
                onClick={() => handleRemoveUser(i)}
                className="px-2 py-1 bg-red-500 text-white rounded"
                disabled={users.length === 1}
              >
                -
              </button>
            </div>
          ))}
          <button
            type="button"
            onClick={handleAddUser}
            className="mt-2 px-3 py-1 bg-blue-500 text-white rounded"
          >
            + Add
          </button>
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
          type="submit"
          disabled={signMutation.isPending}
          className="w-full bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 disabled:opacity-50"
        >
          {signMutation.isPending ? "Signing..." : "Generate Signature"}
        </button>
      </div>
    </form>
  );
};

export default SignPage;
