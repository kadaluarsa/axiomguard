import { useState, createContext, useContext, Children, isValidElement } from 'react'
import { cn } from '@/utils'

interface TabsContextValue {
  activeTab: string
  setActiveTab: (tab: string) => void
}

const TabsContext = createContext<TabsContextValue | null>(null)

function useTabs() {
  const context = useContext(TabsContext)
  if (!context) {
    throw new Error('Tabs components must be used within a Tabs provider')
  }
  return context
}

interface TabsProps {
  defaultTab: string
  children: React.ReactNode
  className?: string
  onValueChange?: (tab: string) => void
}

export function Tabs({ defaultTab, children, className, onValueChange }: TabsProps) {
  const [activeTab, setActiveTab] = useState(defaultTab)

  const handleSetActiveTab = (tab: string) => {
    setActiveTab(tab)
    onValueChange?.(tab)
  }

  return (
    <TabsContext.Provider value={{ activeTab, setActiveTab: handleSetActiveTab }}>
      <div className={cn('w-full', className)}>{children}</div>
    </TabsContext.Provider>
  )
}

interface TabListProps {
  children: React.ReactNode
  className?: string
}

export function TabList({ children, className }: TabListProps) {
  return (
    <div className={cn('flex border-b', className)}>
      {Children.map(children, (child) => {
        if (isValidElement(child) && child.type === Tab) {
          return child
        }
        return null
      })}
    </div>
  )
}

interface TabProps {
  value: string
  children: React.ReactNode
  disabled?: boolean
}

export function Tab({ value, children, disabled }: TabProps) {
  const { activeTab, setActiveTab } = useTabs()
  const isActive = activeTab === value

  return (
    <button
      onClick={() => !disabled && setActiveTab(value)}
      disabled={disabled}
      className={cn(
        'relative px-4 py-2 text-sm font-medium transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        isActive
          ? 'text-foreground'
          : 'text-muted-foreground hover:text-foreground',
        disabled && 'cursor-not-allowed opacity-50'
      )}
    >
      {children}
      {isActive && (
        <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-primary" />
      )}
    </button>
  )
}

interface TabPanelProps {
  value: string
  children: React.ReactNode
}

export function TabPanel({ value, children }: TabPanelProps) {
  const { activeTab } = useTabs()

  if (activeTab !== value) return null

  return <div className="mt-4 animate-fade-in">{children}</div>
}

export default { Tabs, TabList, Tab, TabPanel }
