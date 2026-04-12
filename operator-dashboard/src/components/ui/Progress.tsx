import { cn } from '@/utils'

interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  value: number
  max?: number
  showLabel?: boolean
  size?: 'sm' | 'md' | 'lg'
  variant?: 'default' | 'success' | 'warning' | 'danger'
}

const sizeClasses = {
  sm: 'h-1.5',
  md: 'h-2.5',
  lg: 'h-4',
}

const variantClasses = {
  default: 'bg-primary',
  success: 'bg-green-500',
  warning: 'bg-yellow-500',
  danger: 'bg-red-500',
}

export default function Progress({
  value,
  max = 100,
  showLabel = false,
  size = 'md',
  variant = 'default',
  className,
  ...props
}: ProgressProps) {
  const percentage = Math.min(100, Math.max(0, (value / max) * 100))

  // Auto-variant based on percentage
  const autoVariant =
    variant === 'default'
      ? percentage >= 90
        ? 'danger'
        : percentage >= 75
        ? 'warning'
        : 'default'
      : variant

  return (
    <div className={cn('w-full space-y-1', className)} {...props}>
      <div className={cn('w-full overflow-hidden rounded-full bg-secondary', sizeClasses[size])}>
        <div
          className={cn('h-full transition-all duration-300', variantClasses[autoVariant])}
          style={{ width: `${percentage}%` }}
        />
      </div>
      {showLabel && (
        <div className="flex justify-between text-xs text-muted-foreground">
          <span>{percentage.toFixed(1)}%</span>
          <span>
            {value.toLocaleString()} / {max.toLocaleString()}
          </span>
        </div>
      )}
    </div>
  )
}
