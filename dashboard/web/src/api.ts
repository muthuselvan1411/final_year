/// <reference types="vite/client" />

export type Source = { name: string; label: string; kind: string; available: boolean };

const API = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

export async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API}${path}`);
  if (!response.ok) throw new Error((await response.json()).detail ?? response.statusText);
  return response.json() as Promise<T>;
}

export const apiBase = API;
