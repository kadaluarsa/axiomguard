import { Search, ShieldCheck } from 'lucide-react'
import { cn } from '@/utils'

interface EmptyStateProps {
  title?: string
  description?: string
  message?: string
  icon?: 'search' | 'shield' | 'custom'
  customIcon?: React.ReactNode
  action?: React.ReactNode
  className?: string
}

const icons = {
  search: Search,
  shield: ShieldCheck,
  custom: null,
}

export default function EmptyState({
  title = 'No results found',
  description,
  message,
  icon = 'search',
  customIcon,
  action,
  className,
}: EmptyStateProps) {
  const Icon = icons[icon]
  // Support message as alias for description
  const displayDescription = message || description || 'Try adjusting your filters or search criteria.'

  return (
    <div className={cn('flex flex-col items-center justify-center py-12 text-center', className)}>
      <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-muted">
        {icon === 'custom' ? (
          customIcon
        ) : Icon ? (
          <Icon className="h-8 w-8 text-muted-foreground" />
        ) : null}
      </div>
      <h3 className="text-lg font-semibold">{title}</h3>
      <p className="mt-1 max-w-sm text-sm text-muted-foreground">{displayDescription}</p>
      {action && <div className="mt-6">{action}</div>}
    </div>
  )
}
