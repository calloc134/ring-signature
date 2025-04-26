import { useMutation } from "@tanstack/react-query";
import toast from "react-hot-toast";
import { invoke } from "@tauri-apps/api/core";
import { fetchJson, postJson } from "../api";
import { SignatureVariables, SignatureResult } from "../types";

export function useSign() {
  return useMutation<SignatureResult, Error, SignatureVariables>({
    mutationFn: async ({
      users,
      secretContent,
      password,
      message,
      signerIndex,
    }) => {
      const pubkeys = await fetchJson<string[]>(
        `/keys?names=${users.join(",")}`
      );
      const sig = (await invoke("ring_sign", {
        pubkeys,
        armoredSecret: secretContent,
        password,
        message,
        signerIndex,
      })) as SignatureResult;
      await postJson<SignatureResult>(`/signatures`, {
        v: sig.v,
        xs: sig.xs,
        members: users,
        message,
      });
      return sig;
    },
    onSuccess: () => {
      toast.success("Signature generated and sent");
    },
    onError: (err: Error) => {
      toast.error(err.message);
    },
  });
}
