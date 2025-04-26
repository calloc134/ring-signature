import { useQueryClient } from "@tanstack/react-query";
import { fetchJson } from "../api";
import { invoke } from "@tauri-apps/api/core";
import { SignatureRecord } from "../types";

export function useVerify() {
  const queryClient = useQueryClient();

  const verify = async (rec: SignatureRecord): Promise<boolean> => {
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
    return ok;
  };

  return { verify };
}
