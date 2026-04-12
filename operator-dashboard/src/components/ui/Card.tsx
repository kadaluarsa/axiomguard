import { HTMLAttributes, forwardRef } from 'react'
import { cn } from '@/utils'

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  title?: string
  description?: string
  action?: React.ReactNode
}

const Card = forwardRef<HTMLDivElement, CardProps>(
  ({ className, title, description, action, children, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn('rounded-lg border bg-card text-card-foreground shadow-sm', className)}
        {...props}
      >
        {(title || description || action) && (
          <div className="flex items-center justify-between border-b px-6 py-4">
            <div>
              {title && <h3 className="font-semibold leading-none tracking-tight">{title}</h3>}
              {description && (
                <p className="mt-1.5 text-sm text-muted-foreground">{description}</p>
              )}
            </div>
            {action && <div>{action}</div>}
          </div>
        )}
        <div className="p-6">{children}</div>
      </div>
    )
  }
)
Card.displayName = 'Card'

export default Card
