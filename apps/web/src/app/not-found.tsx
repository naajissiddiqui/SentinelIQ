import Link from 'next/link'
import { ShieldAlert } from 'lucide-react'

export default function NotFound() {
  return (
    <div className="min-h-screen bg-slate-50 flex flex-col items-center justify-center p-6 text-center">
      <div className="w-14 h-14 rounded-2xl bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 mb-4 shadow-sm">
        <ShieldAlert className="w-7 h-7" />
      </div>
      <h1 className="text-2xl font-bold text-slate-900 mb-2">404 - Page Not Found</h1>
      <p className="text-sm text-slate-600 max-w-md mb-6 leading-relaxed">
        The requested resource does not exist or has been relocated within the SentinelIQ security platform.
      </p>
      <Link
        href="/dashboard"
        className="px-5 py-2.5 rounded-xl text-xs font-semibold text-white bg-[#17313E] hover:bg-[#1f4254] transition-colors shadow-sm"
      >
        Return to Dashboard
      </Link>
    </div>
  )
}
