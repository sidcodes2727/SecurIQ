import { createContext, useContext } from 'react';

export type Tone = 'info' | 'good' | 'critical';
export interface ToastApi { push: (title: string, body?: string, tone?: Tone) => void }

export const ToastContext = createContext<ToastApi>({ push: () => {} });
export const useToast = () => useContext(ToastContext);
