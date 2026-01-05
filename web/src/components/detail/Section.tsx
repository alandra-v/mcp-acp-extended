import { cn } from '@/lib/utils'

interface SectionProps {
  number: string
  title: string
  children: React.ReactNode
  className?: string
  loaded?: boolean
}

export function Section({
  number,
  title,
  children,
  className,
  loaded = true,
}: SectionProps) {
  return (
    <div
      className={cn(
        'mb-10',
        loaded ? 'animate-slide-up' : 'opacity-0 translate-y-4',
        className
      )}
      style={
        loaded ? { animationDelay: `${(parseInt(number) - 1) * 100}ms` } : undefined
      }
    >
      <div className="flex items-center gap-4 mb-5">
        <span className="font-mono text-xs text-base-600">{number}</span>
        <span className="font-display text-sm font-semibold uppercase tracking-wide text-base-400">
          {title}
        </span>
        <span
          className={cn(
            'flex-1 h-px bg-[var(--border-subtle)] origin-left',
            loaded && 'animate-line-load'
          )}
          style={
            loaded
              ? { animationDelay: `${(parseInt(number) - 1) * 100 - 50}ms` }
              : undefined
          }
        />
      </div>
      {children}
    </div>
  )
}
