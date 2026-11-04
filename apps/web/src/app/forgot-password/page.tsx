'use client'

import { useRouter } from 'next/navigation'
import { ChevronLeft, KeyRound } from 'lucide-react'
import { STORM, BG, TEXT, MUTED, BORDER, PrimaryBtn } from '@/components/ui'

// Self-service password reset is not implemented on the backend (there is no
// reset endpoint and no email delivery). This page says so instead of
// pretending a reset link was sent.
export default function ForgotPasswordPage() {
  const router = useRouter()

  return (
    <div className="min-h-screen flex items-center justify-center px-4" style={{ backgroundColor: BG }}>
      <div className="w-full max-w-[420px]">
        <button
          onClick={() => router.push('/login')}
          className="flex items-center gap-1.5 text-[13px] mb-6 hover:opacity-70 transition-opacity cursor-pointer"
          style={{ color: MUTED }}
        >
          <ChevronLeft className="w-4 h-4" /> Back to login
        </button>

        <div className="bg-white rounded-2xl border p-8 shadow-sm" style={{ borderColor: BORDER }}>
          <div className="w-14 h-14 rounded-full flex items-center justify-center mx-auto mb-5"
            style={{ backgroundColor: "rgba(65,94,114,0.1)" }}>
            <KeyRound className="w-7 h-7" style={{ color: STORM }} />
          </div>
          <h2 className="text-[20px] font-bold mb-2 text-center" style={{ color: TEXT }}>Password reset</h2>
          <p className="text-[14px] mb-3" style={{ color: MUTED }}>
            Self-service password reset is not available in this SentinelIQ deployment: no reset email can be sent.
          </p>
          <p className="text-[14px] mb-6" style={{ color: MUTED }}>
            Ask an administrator of your organization to restore your access. If you can still sign in, change your
            password under <strong style={{ color: TEXT }}>Settings</strong>.
          </p>
          <PrimaryBtn onClick={() => router.push('/login')}>Return to sign in</PrimaryBtn>
        </div>
      </div>
    </div>
  )
}
