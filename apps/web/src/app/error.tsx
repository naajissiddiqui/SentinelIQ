'use client'

import { useEffect } from 'react'
import { AlertTriangle, RotateCcw } from 'lucide-react'

export default function ErrorBoundary({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    console.error('[SentinelIQ Application Error]:', error)
  }, [error])

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col items-center justify-center p-6 text-center">
      <div className="w-14 h-14 rounded-2xl bg-red-50 border border-red-200 flex items-center justify-center text-red-600 mb-4 shadow-sm">
        <AlertTriangle className="w-7 h-7" />
      </div>
      <h1 className="text-2xl font-bold text-slate-900 mb-2">Application Error</h1>
      <p className="text-sm text-slate-600 max-w-md mb-6 leading-relaxed">
        An unexpected error occurred while rendering this interface.
      </p>
      <div className="flex items-center gap-3">
        <button
          onClick={() => reset()}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-semibold text-white bg-[#17313E] hover:bg-[#1f4254] transition-colors shadow-sm cursor-pointer"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          Retry Request
        </button>
      </div>
    </div>
  )
}
