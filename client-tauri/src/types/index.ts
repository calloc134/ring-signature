export interface UserEntry {
  id: string;
  isSigner: boolean;
}

export interface SignatureVariables {
  users: string[];
  secretContent: string;
  password: string | null;
  message: string;
  signerIndex: number;
}

export interface SignatureResult {
  v: string;
  xs: string[];
}

export interface SignatureRecord {
  id: string;
  message: string;
  v: string;
  xs: string[];
  members: string[];
  created_at: string;
}
