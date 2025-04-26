import { useQuery } from "@tanstack/react-query";
import { fetchJson } from "../api";
import { SignatureRecord } from "../types";

export function useSignatures(username: string) {
  return useQuery<SignatureRecord[], Error>({
    queryKey: ["signatures", username],
    queryFn: () => fetchJson<SignatureRecord[]>(`/signatures/${username}`),
    enabled: false,
  });
}
